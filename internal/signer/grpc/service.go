package grpc

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/koku-web3/go-koku/internal/signer/kms"
	aead "github.com/koku-web3/go-koku/pkg/crypto"
	"github.com/koku-web3/go-koku/pkg/errors"
	log "github.com/koku-web3/go-koku/pkg/logko"
	proto "github.com/koku-web3/go-koku/pkg/proto/signer"
	"github.com/koku-web3/go-koku/pkg/securestore"
	"github.com/koku-web3/go-koku/pkg/securestore/algorithm"
	"github.com/koku-web3/go-koku/pkg/vault/transit"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

// SignerService gRPC 签名服务实现
// 遵循 FINANCE 安全标准：
// - 私钥明文仅在 Signer 内存中短暂存在
// - 所有密钥操作通过 Vault Transit Engine 加密
// - 主密钥种子加密存储，按需解密使用
type SignerService struct {
	proto.UnimplementedSignerServer
	kmsServ *kms.KMS
	grpcSrv *grpc.Server
	host    string
	port    int
	tlsCfg  *tls.Config
}

// NewSignerService 创建新的签名服务实例
func NewSignerService(kms *kms.KMS, host string, port int, tlsCfg *tls.Config) *SignerService {
	return &SignerService{
		kmsServ: kms,
		host:    host,
		port:    port,
		tlsCfg:  tlsCfg,
	}
}

func (s *SignerService) Start(ctx context.Context, opt grpc.ServerOption) error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	if s.tlsCfg != nil {
		creds := credentials.NewTLS(s.tlsCfg)
		s.grpcSrv = grpc.NewServer(grpc.Creds(creds), opt)
		log.Info("Starting gRPC server with mTLS", "address", addr)
	} else {
		s.grpcSrv = grpc.NewServer(opt)
		log.Warn("Starting gRPC server without TLS (insecure)", "address", addr)
	}
	proto.RegisterSignerServer(s.grpcSrv, s)
	reflection.Register(s.grpcSrv)

	go s.StopWhenCancelled(ctx)

	return s.grpcSrv.Serve(lis)
}

func (s *SignerService) StopWhenCancelled(ctx context.Context) {
	<-ctx.Done()
	log.Info("Shutting down gRPC server")
	s.grpcSrv.GracefulStop()
}

// 使用 BIP44 路径 Account=0(运营密钥) 的子密钥签名消息
// 场景：归集、出账
func (s *SignerService) SignAcct0(ctx context.Context, req *proto.SignRequest) (*proto.SignResponse, error) {
	return s.signMessage(req, transit.OperationsTransit, transit.GetKeyNameForOperations, "SignAcct0")
}

// 使用 BIP44 路径 Account=1(用户密钥) 的子密钥签名消息
// 场景：归集
func (s *SignerService) SignAcct1(ctx context.Context, req *proto.SignRequest) (*proto.SignResponse, error) {
	return s.signMessage(req, transit.UserTransit, transit.GetKeyNameForUser, "SignAcct1")
}

type transitKeyNameFunc func(string) string

func (s *SignerService) signMessage(req *proto.SignRequest, transitName string, getKeyName transitKeyNameFunc, methodName string) (*proto.SignResponse, error) {
	log.Debug("Sign received", "trace_id", req.TraceId, "chain_code", req.ChainCode, "bip44_path", req.Bip44Path, "key_type", req.KeyType, "message_length", len(req.Message), "privkey_ciphertext_length", len(req.PrivKeyCiphertext), "dek_ciphertext_length", len(req.DekCiphertext))

	if err := validateSignRequest(req); err != nil {
		log.Warn("Invalid input parameter", "trace_id", req.TraceId, "field", "sign_request", "error", err)
		return nil, errors.InvalidArgument("sign_request")
	}

	msgBytes, err := hex.DecodeString(req.Message)
	if err != nil {
		log.Warn("Invalid input parameter", "trace_id", req.TraceId, "field", "message", "error", err)
		return nil, errors.InvalidArgument("message")
	}

	res, err := s.sign(req.TraceId, transitName, getKeyName(req.ChainCode), req.Bip44Path, req.KeyType, msgBytes, req.PrivKeyCiphertext, req.DekCiphertext)
	if err != nil {
		log.Error("Sign failed", "trace_id", req.TraceId, "error", err)
		return nil, errors.Internal()
	}

	log.Info("Sign succeeded!", "trace_id", req.TraceId, "chain_code", req.ChainCode, "signature_length", len(res.Signature))
	return res, nil
}

// sign 消息签名
// 流程：
// 1. 通过 keyType 获取对应的算法服务 algo
// 2. 用 s.kmsServ.DecryptDataKey 解密 DEK，然后用 DEK 解密私钥信封
// 3. 使用对应的 algo 算法服务对消息进行签名
// 4. 立即清零私钥明文
//
// 安全要点：
// - 私钥明文仅在签名操作期间存在于内存
// - 签名完成后立即清零
// - 所有签名操作都会记录到审计日志
func (s *SignerService) sign(traceId, transitName, keyName, bip44Path, keyType string, msgBytes []byte, privKeyCiphertext, dekCiphertext string) (*proto.SignResponse, error) {
	algo, err := algorithm.Get(keyType)
	if err != nil {
		return nil, fmt.Errorf("unsupported signature algorithm: %s", keyType)
	}

	context := transit.Bip44PathToContext(bip44Path)

	dekPlaintext, err := s.kmsServ.DecryptDataKey(traceId, transitName, keyName, dekCiphertext, context)
	if err != nil {
		return nil, err
	}

	dekBytes, err := base64.StdEncoding.DecodeString(dekPlaintext)
	if err != nil {
		return nil, fmt.Errorf("decode DEK from base64 failed: %w", err)
	}
	defer securestore.Memzero(dekBytes)

	envelopeBytes, err := base64.StdEncoding.DecodeString(privKeyCiphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %w", err)
	}

	if len(envelopeBytes) < aead.NonceSize {
		return nil, fmt.Errorf("invalid envelope bytes length")
	}

	nonce := envelopeBytes[:aead.NonceSize]
	encrypted := envelopeBytes[aead.NonceSize:]

	privateDER, err := aead.Decrypt(encrypted, nonce, dekBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 string: %w", err)
	}
	defer securestore.Memzero(privateDER)

	privateKey, err := algo.ParsePrivateKey(privateDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key from DER: %w", err)
	}
	defer algo.ClearPrivateKey(privateKey)

	signature, err := algo.Sign(privateKey, msgBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	return &proto.SignResponse{
		Signature: hex.EncodeToString(signature),
	}, nil
}

// validateSignRequest 校验 Sign 请求参数
func validateSignRequest(req *proto.SignRequest) error {
	var errors []string

	if req.TraceId == "" {
		errors = append(errors, "trace_id is required")
	}
	if req.ChainCode == "" || len(req.ChainCode) > 32 {
		errors = append(errors, "chain_code must be 1-32 characters")
	}
	if req.Bip44Path == "" || len(req.Bip44Path) > 32 {
		errors = append(errors, "master_key_name must be 1-32 characters")
	}
	if req.KeyType == "" || len(req.KeyType) > 32 {
		errors = append(errors, "key_type must be 1-32 characters")
	}
	if req.Message == "" || len(req.Message) > 1024 {
		errors = append(errors, "message must be 1024 characters")
	}
	if req.PrivKeyCiphertext == "" {
		errors = append(errors, "priv_key_ciphertext is required")
	}
	if req.DekCiphertext == "" {
		errors = append(errors, "dek_ciphertext is required")
	}

	if len(errors) > 0 {
		return fmt.Errorf("%s", strings.Join(errors, "; "))
	}
	return nil
}
