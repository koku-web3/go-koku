// Package signerclient 提供 Signer 服务的 gRPC 客户端
// Coordinator 使用此客户端与 Signer 服务通信
package signerclient

import (
	"context"
	"fmt"

	signergrpc "github.com/koku-web3/go-koku/internal/signer/grpc"
	"github.com/koku-web3/go-koku/pkg/bip44"
	log "github.com/koku-web3/go-koku/pkg/logko"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Client Signer 服务客户端
type Client struct {
	conn    *grpc.ClientConn
	signer  signergrpc.SignerClient
	address string
}

// NewClient 创建新的 Signer 客户端
func NewClient(addr string) (*Client, error) {
	if addr == "" {
		return nil, fmt.Errorf("address is required")
	}

	// TODO: 生产环境应使用 mTLS 凭证
	conn, err := grpc.NewClient(
		addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}

	return &Client{
		conn:    conn,
		signer:  signergrpc.NewSignerClient(conn),
		address: addr,
	}, nil
}

// Close 关闭连接
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Address 获取服务地址
func (c *Client) Address() string {
	return c.address
}

// ===== 请求/响应类型 =====

// CreateMasterKeyResult 创建主密钥结果
type CreateMasterKeyResult struct {
	TraceID        string
	KeyName        string
	SeedCiphertext string
	PublicKey      string
	BIP44Path      string
}

// CreateDerivedKeyResult 创建派生密钥结果
type CreateDerivedKeyResult struct {
	TraceID           string
	KeyName           string
	PrivKeyCiphertext string
	PublicKey         string
	BIP44Path         string
	KeyContext        string
}

// SignResult 签名结果
type SignResult struct {
	TraceID   string
	Signature string
}

// ===== 业务方法 =====

// CreateMasterKey 创建主密钥
func (c *Client) CreateMasterKey(ctx context.Context, traceID, chainCode, keyType string) (*CreateMasterKeyResult, error) {
	log.Info("CreateMasterKey",
		"trace_id", traceID,
		"chain_code", chainCode,
		"key_type", keyType)

	// 调用 Signer gRPC
	resp, err := c.signer.CreateMasterKey(ctx, &signergrpc.CreateMasterKeyRequest{
		TraceId:   traceID,
		ChainCode: chainCode,
		KeyType:   keyType,
	})
	if err != nil {
		log.Error("CreateMasterKey failed", "error", err, "trace_id", traceID)
		return nil, fmt.Errorf("signer CreateMasterKey failed: %w", err)
	}

	// 返回结果
	bip44Path, err := bip44.MasterKeyBIP44Path(chainCode)
	if err != nil {
		return nil, fmt.Errorf("unsupported chain: %s", chainCode)
	}

	return &CreateMasterKeyResult{
		TraceID:        traceID,
		KeyName:        resp.KeyName,
		SeedCiphertext: resp.Seed,
		BIP44Path:      bip44Path,
	}, nil
}

// CreateDerivedKey 创建派生密钥
// masterKeyPemCiphertext: 主密钥的 PEM 密文（来自 CreateMasterKey 的返回值）
func (c *Client) CreateDerivedKey(ctx context.Context, traceID, chain, masterKeyName string, masterKeyPemCiphertext string, usage int32, keyType string, addressIndex uint32) (*CreateDerivedKeyResult, error) {
	log.Info("CreateDerivedKey",
		"trace_id", traceID,
		"chain", chain,
		"master_key_name", masterKeyName,
		"usage", usage,
		"address_index", addressIndex)

	// 验证链是否支持 BIP-44
	coinType, err := bip44.CoinTypeFromChainCode(chain)
	if err != nil {
		return nil, fmt.Errorf("unsupported chain: %s", chain)
	}

	// 计算 BIP-44 路径
	path := bip44.FromUsage(coinType, bip44.KeyUsage(usage), addressIndex)

	// 构造 Signer 请求
	req := &signergrpc.CreateKeyRequest{
		TraceId:                traceID,
		ChainCode:              chain,
		MasterKeyName:          masterKeyName,
		MasterKeyPemCiphertext: masterKeyPemCiphertext,
		KeyContext:             path.ToContext(),
		KeyUsage:               signergrpc.KeyUsage(usage),
		KeyType:                keyType,
		Account:                path.Account - 0x80000000,
		Change:                 path.Change,
		AddressIndex:           addressIndex,
	}

	// 调用 Signer gRPC
	resp, err := c.signer.CreateKey(ctx, req)
	if err != nil {
		log.Error("CreateDerivedKey failed", "error", err, "trace_id", traceID)
		return nil, fmt.Errorf("signer CreateKey failed: %w", err)
	}

	// 返回结果
	return &CreateDerivedKeyResult{
		TraceID:           traceID,
		KeyName:           bip44.GenerateDerivedKeyName(chain, bip44.KeyUsage(usage), addressIndex),
		PrivKeyCiphertext: resp.PrivKeyCiphertext,
		PublicKey:         resp.PublicKey,
		BIP44Path:         path.String(),
		KeyContext:        path.ToContext(),
	}, nil
}

// Sign 签名消息
func (c *Client) Sign(ctx context.Context, traceID, chain, keyName string, usage int32, keyType, keyContext, message, privKeyCiphertext string) (*SignResult, error) {
	log.Info("Sign",
		"trace_id", traceID,
		"chain", chain,
		"key_name", keyName)

	// 构造 Signer 请求
	req := &signergrpc.SignRequest{
		TraceId:           traceID,
		ChainCode:         chain,
		MasterKeyName:     keyName,
		KeyName:           keyName,
		KeyUsage:          signergrpc.KeyUsage(usage),
		KeyContext:        keyContext,
		KeyType:           keyType,
		Message:           message,
		PrivKeyCiphertext: privKeyCiphertext,
	}

	// 调用 Signer gRPC
	resp, err := c.signer.Sign(ctx, req)
	if err != nil {
		log.Error("Sign failed", "error", err, "trace_id", traceID)
		return nil, fmt.Errorf("signer Sign failed: %w", err)
	}

	// 返回签名结果
	return &SignResult{
		TraceID:   traceID,
		Signature: resp.Signature,
	}, nil
}
