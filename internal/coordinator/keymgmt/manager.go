// Package keymgmt 实现了密钥生命周期管理
// 协调 Coordinator 和 Signer 服务之间的密钥操作
// 遵循 FINANCE 安全标准：私钥明文仅在 Signer 内存中短暂存在
package keymgmt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	signerpb "github.com/koku-web3/go-koku/internal/signer/grpc"
	"github.com/koku-web3/go-koku/pkg/bip44"
	log "github.com/koku-web3/go-koku/pkg/logko"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// KeyManager 密钥管理器
// 负责协调 Coordinator 和 Signer 服务，管理密钥生命周期
type KeyManager struct {
	signerConn   *grpc.ClientConn
	signerClient signerpb.SignerClient
}

// NewKeyManager 创建密钥管理器
func NewKeyManager(signerAddr string) (*KeyManager, error) {
	// 创建到 Signer 的 gRPC 连接
	conn, err := grpc.NewClient(
		signerAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection to signer: %w", err)
	}

	return &KeyManager{
		signerConn:   conn,
		signerClient: signerpb.NewSignerClient(conn),
	}, nil
}

// Close 关闭 gRPC 连接
func (km *KeyManager) Close() error {
	if km.signerConn != nil {
		return km.signerConn.Close()
	}
	return nil
}

// MasterKeyResult 主密钥创建结果
type MasterKeyResult struct {
	KeyName        string // 密钥名称，如 "eth-master-key"
	SeedCiphertext string // Vault 加密的种子密文
	PublicKey      string // 公钥 (Hex)
}

// CreateMasterKey 创建链主密钥
// 在 Signer 中生成 HD 主密钥，用 Vault Transit Engine 加密后返回密文
func (km *KeyManager) CreateMasterKey(ctx context.Context, traceID, chainCode, keyType string) (*MasterKeyResult, error) {
	log.Info("Creating master key",
		"trace_id", traceID,
		"chain_code", chainCode,
		"key_type", keyType)

	// 验证链是否支持 BIP-44
	coinType, err := bip44.CoinTypeFromChainCode(chainCode)
	if err != nil {
		return nil, fmt.Errorf("unsupported chain: %w", err)
	}

	// 调用 Signer 创建主密钥
	resp, err := km.signerClient.CreateMasterKey(ctx, &signerpb.CreateMasterKeyRequest{
		TraceId:   traceID,
		ChainCode: chainCode,
		KeyType:   keyType,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	result := &MasterKeyResult{
		KeyName:        resp.KeyName,
		SeedCiphertext: resp.Seed, // Vault 加密的种子密文
	}

	log.Info("Master key created successfully",
		"trace_id", traceID,
		"chain_code", chainCode,
		"key_name", resp.KeyName,
		"bip44_path", fmt.Sprintf("m/44'/%d'/0'/0/0", coinType))

	return result, nil
}

// CreateSubKeyResult 子密钥创建结果
type CreateSubKeyResult struct {
	KeyName           string // 派生密钥名称，格式：{chain}-child-{op|user}-{index}
	PrivKeyCiphertext string // Vault 加密的私钥密文
	PublicKey         string // 公钥 (Hex)
	BIP44Path         string // BIP-44 路径字符串
	KeyContext        string // Vault context
}

// CreateSubKey 创建运营或用户密钥
// 从主密钥派生子密钥，用 Vault Transit Engine (derived=true) 加密后返回
// masterKeyPemCiphertext: 主密钥的 PEM 密文（来自 CreateMasterKey 的返回值）
func (km *KeyManager) CreateSubKey(
	ctx context.Context,
	traceID, chainCode, keyType string,
	masterKeyName string,
	masterKeyPemCiphertext string,
	usage bip44.KeyUsage,
	addressIndex uint32,
) (*CreateSubKeyResult, error) {
	log.Info("Creating sub key",
		"trace_id", traceID,
		"chain_code", chainCode,
		"master_key_name", masterKeyName,
		"usage", usage,
		"address_index", addressIndex)

	// 验证链是否支持
	coinType, err := bip44.CoinTypeFromChainCode(chainCode)
	if err != nil {
		return nil, fmt.Errorf("unsupported chain: %w", err)
	}

	// 根据用途确定 BIP-44 路径
	path := bip44.FromUsage(coinType, usage, addressIndex)
	keyContext := path.ToContext()

	// BIP-44 参数
	var account, change uint32
	switch usage {
	case bip44.Operational:
		account = 0
		change = 1 // 运营用途使用内部链
	case bip44.User:
		account = 1
		change = 1 // 用户密钥使用内部链
	case bip44.Backup:
		account = 2
		change = 0 // 备份密钥使用外部链
	}

	// 根据用途确定 proto KeyUsage
	var protoKeyUsage signerpb.KeyUsage
	switch usage {
	case bip44.Operational:
		protoKeyUsage = signerpb.KeyUsage_KEY_USAGE_OPERATIONAL
	case bip44.User:
		protoKeyUsage = signerpb.KeyUsage_KEY_USAGE_USER
	default:
		protoKeyUsage = signerpb.KeyUsage_KEY_USAGE_OPERATIONAL
	}

	// 调用 Signer 创建子密钥
	resp, err := km.signerClient.CreateKey(ctx, &signerpb.CreateKeyRequest{
		TraceId:                traceID,
		ChainCode:              chainCode,
		MasterKeyName:          masterKeyName,
		MasterKeyPemCiphertext: masterKeyPemCiphertext,
		KeyContext:             keyContext,
		KeyUsage:               protoKeyUsage,
		KeyType:                keyType,
		Account:                account,
		Change:                 change,
		AddressIndex:           addressIndex,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create sub key: %w", err)
	}

	result := &CreateSubKeyResult{
		KeyName:           fmt.Sprintf("%s-child-%s-%d", chainCode, usage.String(), addressIndex),
		PrivKeyCiphertext: resp.PrivKeyCiphertext,
		PublicKey:         resp.PublicKey,
		BIP44Path:         path.String(),
		KeyContext:        keyContext,
	}

	log.Info("Sub key created successfully",
		"trace_id", traceID,
		"key_name", result.KeyName,
		"bip44_path", result.BIP44Path)

	return result, nil
}

// SignResult 签名结果
type SignResult struct {
	Signature string // 签名 (Hex)
}

// Sign 签名消息
// 使用指定密钥对消息进行签名
func (km *KeyManager) Sign(
	ctx context.Context,
	traceID, chainCode, keyType, keyName string,
	usage bip44.KeyUsage,
	privKeyCiphertext string,
	keyContext string,
	message string,
) (*SignResult, error) {
	log.Info("Signing message",
		"trace_id", traceID,
		"chain_code", chainCode,
		"key_name", keyName,
		"usage", usage,
		"message_hash", sha256Hex(message))

	// 根据用途确定 proto KeyUsage
	var protoKeyUsage signerpb.KeyUsage
	switch usage {
	case bip44.Operational:
		protoKeyUsage = signerpb.KeyUsage_KEY_USAGE_OPERATIONAL
	case bip44.User:
		protoKeyUsage = signerpb.KeyUsage_KEY_USAGE_USER
	default:
		protoKeyUsage = signerpb.KeyUsage_KEY_USAGE_OPERATIONAL
	}

	// 派生密钥名称 (与 Signer 中的 generateDerivedKeyName 保持一致)
	// 注意：这里需要从 keyName 中解析出 addressIndex
	// keyName 格式: {chain}-child-{op|user}-{index}
	var addressIndex uint32
	var suffix string
	_, err := fmt.Sscanf(keyName, "%*[^:]-child-%s-%d", &suffix, &addressIndex)
	if err != nil {
		// 如果解析失败，使用默认值 0
		addressIndex = 0
	}

	// 调用 Signer 执行签名
	resp, err := km.signerClient.Sign(ctx, &signerpb.SignRequest{
		TraceId:           traceID,
		ChainCode:         chainCode,
		MasterKeyName:     fmt.Sprintf("%s-master-key", chainCode), // 主密钥名称
		KeyName:           keyName,                                 // 派生密钥名称
		KeyUsage:          protoKeyUsage,                           // 密钥用途
		KeyContext:        keyContext,                              // 派生上下文
		KeyType:           keyType,
		Message:           message,
		PrivKeyCiphertext: privKeyCiphertext,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	result := &SignResult{
		Signature: resp.Signature,
	}

	log.Info("Sign completed successfully",
		"trace_id", traceID,
		"signature_len", len(result.Signature))

	return result, nil
}

// sha256Hex 计算字符串的 SHA256 哈希（用于日志）
func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// KeyInfo 密钥信息
type KeyInfo struct {
	KeyName    string `json:"key_name"`
	ChainCode  string `json:"chain_code"`
	PublicKey  string `json:"public_key"`
	BIP44Path  string `json:"bip44_path"`
	KeyContext string `json:"key_context"`
	Status     string `json:"status"`
}
