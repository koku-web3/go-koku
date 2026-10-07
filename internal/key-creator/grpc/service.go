package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/koku-web3/go-koku/internal/key-creator/kms"
	proto "github.com/koku-web3/go-koku/pkg/proto/key-creator"
	log "github.com/koku-web3/logko"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

// KeyCreatorService gRPC 签名服务实现
// 遵循 FINANCE 安全标准：
// - 私钥明文仅在 KeyCreator 内存中短暂存在
// - 所有密钥操作通过 KMS（Vault Transit Engine） 加密
// - 运营密钥与用户密钥从使用到存储全方位隔离
// - 主密钥种子加密存储，按需解密使用
type KeyCreatorService struct {
	proto.UnimplementedKeyCreatorServer
	kmsServ *kms.KMS
	grpcSrv *grpc.Server
	host    string
	port    int
	tlsCfg  *tls.Config
}

// NewKeyCreatorService 创建新的签名服务实例
func NewKeyCreatorService(
	kms *kms.KMS,
	host string,
	port int,
	tlsCfg *tls.Config,
) *KeyCreatorService {
	return &KeyCreatorService{
		kmsServ: kms,
		host:    host,
		port:    port,
		tlsCfg:  tlsCfg,
	}
}

func (s *KeyCreatorService) Start(ctx context.Context, opt grpc.ServerOption) error {
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
	proto.RegisterKeyCreatorServer(s.grpcSrv, s)
	reflection.Register(s.grpcSrv)

	go s.StopWhenCancelled(ctx)

	return s.grpcSrv.Serve(lis)
}

func (s *KeyCreatorService) StopWhenCancelled(ctx context.Context) {
	<-ctx.Done()
	log.Info("Shutting down gRPC server")
	s.grpcSrv.GracefulStop()
}
