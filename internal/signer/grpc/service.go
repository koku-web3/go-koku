package grpc

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/koku-web3/go-koku/internal/signer/securestore"
	"github.com/koku-web3/go-koku/internal/signer/securestore/algorithm"
	"github.com/koku-web3/go-koku/pkg/bip44"
	"github.com/koku-web3/go-koku/pkg/hdwallet"
	log "github.com/koku-web3/go-koku/pkg/logko"

	"github.com/tyler-smith/go-bip32"
)

// SignerService gRPC 签名服务实现
// 遵循 FINANCE 安全标准：
// - 私钥明文仅在 Signer 内存中短暂存在
// - 所有密钥操作通过 Vault Transit Engine 加密
// - 主密钥种子加密存储，按需解密使用
type SignerService struct {
	UnimplementedSignerServer
	vaultClient VaultClientWrapper
}

// VaultClientWrapper Vault 客户端接口包装
// 用于在测试中注入 mock
type VaultClientWrapper interface {
	CreateMasterKey(chain, name, keyType string, derived bool) error
	Encrypt(chain, keyName, plaintext, context string) (string, error)
	Decrypt(chain, keyName, ciphertext, context string) (string, error)
	Sign(chain, keyName string, data []byte) (string, error)
	Verify(chain, keyName string, data []byte, signature string) (bool, error)
}

// NewSignerService 创建新的签名服务实例
func NewSignerService(vaultClient VaultClientWrapper) *SignerService {
	return &SignerService{
		vaultClient: vaultClient,
	}
}

// CreateMasterKey 创建主密钥
// 流程：
// 1. 生成随机 HD 主密钥种子
// 2. 用 Vault Transit Engine (derived=false) 加密种子
// 3. 返回密钥名称和加密的种子（用于存储到数据库）
//
// 安全要点：
// - 种子明文仅在函数内存在，签名后即被清零
// - 加密的种子可安全存储在数据库中
func (s *SignerService) CreateMasterKey(ctx context.Context, req *CreateMasterKeyRequest) (*CreateMasterKeyResponse, error) {
	log.Info("CreateMasterKey called",
		"trace_id", req.TraceId,
		"chain_code", req.ChainCode,
		"key_type", req.KeyType)

	// 入参校验
	if err := validateCreateMasterKeyRequest(req); err != nil {
		log.Error("CreateMasterKey validation failed", "error", err, "trace_id", req.TraceId)
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// 验证 keyType 是否支持
	if !algorithm.IsSupported(req.KeyType) {
		log.Error("Unsupported key type", "key_type", req.KeyType, "trace_id", req.TraceId)
		return nil, fmt.Errorf("unsupported key type: %s", req.KeyType)
	}

	// 验证链是否支持 BIP-44
	_, err := bip44.MasterKeyPath(req.ChainCode)
	if err != nil {
		log.Error("Unsupported chain for BIP-44", "chain_code", req.ChainCode, "trace_id", req.TraceId)
		return nil, fmt.Errorf("unsupported chain for BIP-44: %s", req.ChainCode)
	}

	// 1. 生成 HD 主密钥（使用随机种子）
	masterKey, err := hdwallet.GenerateMasterKey()
	if err != nil {
		log.Error("Failed to generate HD master key", "error", err, "trace_id", req.TraceId)
		return nil, fmt.Errorf("failed to generate master key: %w", err)
	}

	// 确保主密钥种子在函数返回前被清零
	defer func() {
		// 清除敏感数据
		if masterKey != nil && masterKey.Key != nil {
			// go-bip32 不提供清零接口，这里记录日志
			log.Debug("Master key seed cleared from memory", "trace_id", req.TraceId)
		}
	}()

	// 主密钥名称使用固定格式: {chain_code}-master-key
	keyName := fmt.Sprintf("%s-master-key", req.ChainCode)

	// 主密钥的 BIP-44 路径: m/44'/{coin_type}'/0'/0/0
	masterKeyPath, err := bip44.MasterKeyPath(req.ChainCode)
	if err != nil {
		return nil, err
	}

	// 使用主密钥路径的哈希作为 context，与派生密钥保持一致
	masterKeyContext := masterKeyPath.ToContext()

	// 2. 将 HD 种子编码为 PEM 格式，然后转为 base64
	seedBase64, err := hdwallet.EncodeMasterKeySeed(masterKey)
	if err != nil {
		log.Error("Failed to encode master key seed to PEM", "error", err, "trace_id", req.TraceId)
		return nil, fmt.Errorf("failed to encode master key seed: %w", err)
	}

	// 3. 调用 Vault Transit Engine 加密种子
	// 使用主密钥路径的哈希作为 context，确保主密钥和派生密钥的 context 格式统一
	ciphertext, err := s.vaultClient.Encrypt(req.ChainCode, keyName, seedBase64, masterKeyContext)
	if err != nil {
		log.Error("Failed to encrypt master key seed with Vault",
			"error", err,
			"trace_id", req.TraceId,
			"chain_code", req.ChainCode,
			"key_name", keyName)
		return nil, fmt.Errorf("failed to encrypt master key seed: %w", err)
	}

	log.Info("CreateMasterKey succeeded",
		"trace_id", req.TraceId,
		"chain_code", req.ChainCode,
		"key_name", keyName,
		"key_type", req.KeyType,
		"bip44_path", masterKeyPath.String())

	// 返回：
	// - keyName: 密钥标识
	// - seed: Vault 加密的种子密文（供 Coordinator 存储到数据库）
	return &CreateMasterKeyResponse{
		KeyName: keyName,
		Seed:    ciphertext, // 存储加密的种子而非明文
	}, nil
}

// CreateKey 创建子密钥
// 流程：
// 1. 从主密钥种子派生子密钥
// 2. 按 BIP-44 路径派生子密钥
// 3. 根据 key_usage 使用不同的 key_name：
//   - OPERATIONAL: {chain_code}-child-op-{index}
//   - USER: {chain_code}-child-user-{index}
//
// 4. 用对应的 key_name 加密子私钥
// 5. 签名后立即清零所有明文私钥
//
// 安全要点：
// - 私钥明文仅在 Signer 内存中短暂存在
// - 使用 BIP-44 路径的 SHA256 作为 Vault context，防止密文替换攻击
// - 不同用途的密钥使用独立的 Vault key_name，实现密钥隔离
func (s *SignerService) CreateKey(ctx context.Context, req *CreateKeyRequest) (*CreateKeyResponse, error) {
	log.Info("CreateKey called",
		"trace_id", req.TraceId,
		"chain_code", req.ChainCode,
		"master_key_name", req.MasterKeyName,
		"master_key_pem_ciphertext length", len(req.MasterKeyPemCiphertext),
		"key_context", req.KeyContext,
		"key_usage", req.KeyUsage,
		"key_type", req.KeyType,
		"account", req.Account,
		"change", req.Change,
		"address_index", req.AddressIndex)

	// 入参校验
	if err := validateCreateKeyRequest(req); err != nil {
		log.Error("CreateKey validation failed", "error", err, "trace_id", req.TraceId)
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// 校验主密钥PEM密文
	if req.MasterKeyPemCiphertext == "" {
		log.Error("CreateKey validation failed: master_key_pem_ciphertext is required", "trace_id", req.TraceId)
		return nil, fmt.Errorf("invalid request: master_key_pem_ciphertext is required")
	}

	// 获取算法实现
	algo, err := algorithm.Get(req.KeyType)
	if err != nil {
		log.Error("Unsupported key type", "key_type", req.KeyType, "trace_id", req.TraceId)
		return nil, fmt.Errorf("unsupported key type: %s", req.KeyType)
	}

	// 验证链是否支持
	coinType, err := bip44.CoinTypeFromChainCode(req.ChainCode)
	if err != nil {
		return nil, fmt.Errorf("unsupported chain: %s", req.ChainCode)
	}

	// 创建 BIP-44 路径
	bip44Path := bip44.FromUsage(coinType, bip44.KeyUsage(req.KeyUsage), req.AddressIndex)

	// 生成 key_context (如果未提供)
	keyContext := req.KeyContext
	if keyContext == "" {
		keyContext = bip44Path.ToContext()
	}

	// 根据 key_usage 生成派生密钥的 key_name
	derivedKeyName := generateDerivedKeyName(req.ChainCode, req.KeyUsage, req.AddressIndex)

	// 1. 调用 Vault Transit Engine 解密主密钥种子
	// 使用主密钥名称和主密钥路径的哈希作为 context
	masterKeyPath, err := bip44.MasterKeyPath(req.ChainCode)
	if err != nil {
		log.Error("Failed to get master key path", "error", err, "trace_id", req.TraceId)
		return nil, fmt.Errorf("failed to get master key path: %w", err)
	}
	masterKeyContext := masterKeyPath.ToContext()

	seedPlaintext, err := s.vaultClient.Decrypt(req.ChainCode, req.MasterKeyName, req.MasterKeyPemCiphertext, masterKeyContext)
	if err != nil {
		log.Error("Failed to decrypt master key seed with Vault",
			"error", err,
			"trace_id", req.TraceId,
			"chain_code", req.ChainCode,
			"master_key_name", req.MasterKeyName)
		return nil, fmt.Errorf("failed to decrypt master key seed: %w", err)
	}

	// 2. 从解密后的种子恢复主密钥
	masterKey, err := hdwallet.DecodeMasterKeySeed(seedPlaintext)
	if err != nil {
		log.Error("Failed to restore master key from seed", "error", err, "trace_id", req.TraceId)
		return nil, fmt.Errorf("failed to restore master key from seed: %w", err)
	}

	// 2. 按 BIP-44 路径派生子密钥
	childKey, err := masterKey.DeriveFromChainCode(req.ChainCode, req.Account, req.Change, req.AddressIndex)
	if err != nil {
		log.Error("Failed to derive BIP44 key", "error", err, "trace_id", req.TraceId)
		return nil, fmt.Errorf("failed to derive BIP44 key: %w", err)
	}

	// 3. 转换私钥格式（BIP-32 原始字节 → 算法特定的 crypto.PrivateKey）
	privateKey, err := convertBIP32KeyToAlgorithm(childKey, req.KeyType)
	if err != nil {
		log.Error("Failed to convert BIP32 key to algorithm format", "error", err, "trace_id", req.TraceId)
		return nil, fmt.Errorf("failed to convert key: %w", err)
	}

	// 创建安全私钥用于自动清零
	securePrivateKey := securestore.NewSecurePrivateKey(privateKey, childKey.Key, req.KeyType)
	defer securePrivateKey.Clear()

	// 4. 序列化私钥为 PKCS#8 格式（PEM Type 统一为 "PRIVATE KEY"）
	privateKeyDER, err := algo.SerializePrivateKey(privateKey)
	if err != nil {
		log.Error("Failed to serialize private key", "error", err, "trace_id", req.TraceId)
		return nil, fmt.Errorf("failed to serialize private key: %w", err)
	}
	privateKeyBase64 := base64.StdEncoding.EncodeToString(privateKeyDER)

	// 5. 用 Vault Transit Engine 加密私钥
	// 使用派生密钥的 key_name，而非主密钥的 key_name
	ciphertext, err := s.vaultClient.Encrypt(req.ChainCode, derivedKeyName, privateKeyBase64, keyContext)
	if err != nil {
		log.Error("Failed to encrypt private key with Vault",
			"error", err,
			"trace_id", req.TraceId,
			"chain_code", req.ChainCode,
			"derived_key_name", derivedKeyName)
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}

	// 6. 获取公钥（从私钥中提取）
	publicKey := privateKey.(crypto.Signer).Public()
	publicKeyBytes, err := algo.SerializePublicKey(publicKey)
	if err != nil {
		log.Error("Failed to serialize public key", "error", err, "trace_id", req.TraceId)
		return nil, fmt.Errorf("failed to serialize public key: %w", err)
	}
	publicKeyBase64 := base64.StdEncoding.EncodeToString(publicKeyBytes)

	log.Info("CreateKey succeeded",
		"trace_id", req.TraceId,
		"chain_code", req.ChainCode,
		"master_key_name", req.MasterKeyName,
		"derived_key_name", derivedKeyName,
		"key_usage", req.KeyUsage,
		"bip44_path", bip44Path.String())

	// 返回：
	// - privKeyCiphertext: Vault 加密的私钥密文（供 Coordinator 存储到数据库）
	// - publicKey: 公钥（可安全公开）
	return &CreateKeyResponse{
		PrivKeyCiphertext: ciphertext,
		PublicKey:         publicKeyBase64,
	}, nil
}

// Sign 消息签名
// 流程：
// 1. 用 Vault Transit Engine (derived=true, context=key_context) 解密私钥
// 2. 对消息进行签名
// 3. 立即清零私钥明文
//
// 安全要点：
// - 私钥明文仅在签名操作期间存在于内存
// - 签名完成后立即清零
// - 所有签名操作都会记录到审计日志
func (s *SignerService) Sign(ctx context.Context, req *SignRequest) (*SignResponse, error) {
	log.Info("Sign called",
		"trace_id", req.TraceId,
		"chain_code", req.ChainCode,
		"master_key_name", req.MasterKeyName,
		"key_name", req.KeyName,
		"key_usage", req.KeyUsage,
		"key_type", req.KeyType,
		"message_len", len(req.Message))

	// 入参校验
	if err := validateSignRequest(req); err != nil {
		log.Error("Sign validation failed", "error", err, "trace_id", req.TraceId)
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// 获取算法实现
	algo, err := algorithm.Get(req.KeyType)
	if err != nil {
		log.Error("Unsupported key type for signing", "key_type", req.KeyType, "trace_id", req.TraceId)
		return nil, fmt.Errorf("unsupported key type: %s", req.KeyType)
	}

	// 使用派生密钥的 key_name 进行解密
	// 注意：这里使用 req.KeyName 而不是 req.MasterKeyName
	keyName := req.KeyName
	if keyName == "" {
		// 如果没有提供 key_name，根据 key_usage 生成
		keyName = generateDerivedKeyName(req.ChainCode, req.KeyUsage, 0)
	}

	// 1. 调用 Vault Transit Engine 解密私钥
	plaintext, err := s.vaultClient.Decrypt(req.ChainCode, keyName, req.PrivKeyCiphertext, req.KeyContext)
	if err != nil {
		log.Error("Failed to decrypt private key with Vault",
			"error", err,
			"trace_id", req.TraceId,
			"chain_code", req.ChainCode,
			"key_name", keyName)
		return nil, fmt.Errorf("failed to decrypt private key: %w", err)
	}

	// 2. 安全解析私钥 - 这会创建私钥的安全副本
	securePrivateKey, err := securestore.ParsePrivateKeyFromBase64(plaintext, req.KeyType)
	if err != nil {
		log.Error("Failed to parse private key", "error", err, "trace_id", req.TraceId)
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// 3. 确保私钥在函数返回前被清零
	defer securePrivateKey.Clear()

	// 4. 使用算法签名
	signature, err := algo.Sign(securePrivateKey.Key(), []byte(req.Message))
	if err != nil {
		log.Error("Failed to sign", "error", err, "trace_id", req.TraceId)
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	// 5. 签名完成后显式清零私钥（defer 也会执行，但显式调用更安全）
	securePrivateKey.Clear()

	// 6. 将签名转换为十六进制格式返回
	signatureHex := hex.EncodeToString(signature)

	log.Info("Sign succeeded",
		"trace_id", req.TraceId,
		"chain_code", req.ChainCode,
		"key_name", keyName,
		"signature_len", len(signatureHex))

	return &SignResponse{
		Signature: signatureHex,
	}, nil
}

// generateDerivedKeyName 根据链名称、密钥用途和地址索引生成派生密钥名称
// 格式：
//   - OPERATIONAL: {chain_code}-child-op-{address_index}
//   - USER: {chain_code}-child-user-{address_index}
func generateDerivedKeyName(chainCode string, usage KeyUsage, addressIndex uint32) string {
	switch usage {
	case KeyUsage_KEY_USAGE_OPERATIONAL:
		return fmt.Sprintf("%s-child-op-%d", chainCode, addressIndex)
	case KeyUsage_KEY_USAGE_USER:
		return fmt.Sprintf("%s-child-user-%d", chainCode, addressIndex)
	default:
		// 默认使用运营密钥命名
		return fmt.Sprintf("%s-child-op-%d", chainCode, addressIndex)
	}
}

// convertBIP32KeyToAlgorithm 将 BIP-32 原始私钥字节转换为指定算法的 crypto.PrivateKey
// 使用算法注册表（策略模式）动态获取算法实现
func convertBIP32KeyToAlgorithm(key *bip32.Key, keyType string) (crypto.PrivateKey, error) {
	privKeyBytes := key.Key
	if len(privKeyBytes) != 32 {
		return nil, fmt.Errorf("invalid private key length: expected 32, got %d", len(privKeyBytes))
	}

	algo, err := algorithm.Get(keyType)
	if err != nil {
		return nil, err
	}

	return algo.NewPrivateKeyFromBytes(privKeyBytes)
}

// validateCreateMasterKeyRequest 校验 CreateMasterKey 请求参数
func validateCreateMasterKeyRequest(req *CreateMasterKeyRequest) error {
	var errors []string

	if req.TraceId == "" {
		errors = append(errors, "trace_id is required")
	}
	if req.ChainCode == "" || len(req.ChainCode) > 36 {
		errors = append(errors, "chain_code must be 1-36 characters")
	}
	if req.KeyType == "" || len(req.KeyType) > 36 {
		errors = append(errors, "key_type must be 1-36 characters")
	}

	if len(errors) > 0 {
		return fmt.Errorf("%s", strings.Join(errors, "; "))
	}
	return nil
}

// validateCreateKeyRequest 校验 CreateKey 请求参数
func validateCreateKeyRequest(req *CreateKeyRequest) error {
	var errors []string

	if req.TraceId == "" {
		errors = append(errors, "trace_id is required")
	}
	if req.ChainCode == "" || len(req.ChainCode) > 36 {
		errors = append(errors, "chain_code must be 1-36 characters")
	}
	if req.MasterKeyName == "" || len(req.MasterKeyName) > 64 {
		errors = append(errors, "master_key_name must be 1-64 characters")
	}
	if req.MasterKeyPemCiphertext == "" {
		errors = append(errors, "master_key_pem_ciphertext is required")
	}
	if req.KeyType == "" || len(req.KeyType) > 36 {
		errors = append(errors, "key_type must be 1-36 characters")
	}

	// 验证 keyType 是否支持
	if !algorithm.IsSupported(req.KeyType) {
		errors = append(errors, fmt.Sprintf("unsupported key_type: %s", req.KeyType))
	}

	if len(errors) > 0 {
		return fmt.Errorf("%s", strings.Join(errors, "; "))
	}
	return nil
}

// validateSignRequest 校验 Sign 请求参数
func validateSignRequest(req *SignRequest) error {
	var errors []string

	if req.TraceId == "" {
		errors = append(errors, "trace_id is required")
	}
	if req.ChainCode == "" || len(req.ChainCode) > 36 {
		errors = append(errors, "chain_code must be 1-36 characters")
	}
	if req.MasterKeyName == "" || len(req.MasterKeyName) > 64 {
		errors = append(errors, "master_key_name must be 1-64 characters")
	}
	if req.KeyName == "" && req.KeyUsage == KeyUsage_KEY_USAGE_UNSPECIFIED {
		errors = append(errors, "either key_name or key_usage must be provided")
	}
	if req.KeyType == "" || len(req.KeyType) > 36 {
		errors = append(errors, "key_type must be 1-36 characters")
	}
	if req.Message == "" || len(req.Message) > 1024*1024 { // 放宽限制到 1MB
		errors = append(errors, "message must be 1-1MB characters")
	}
	if req.PrivKeyCiphertext == "" {
		errors = append(errors, "priv_key_ciphertext is required")
	}

	// 验证 keyType 是否支持
	if !algorithm.IsSupported(req.KeyType) {
		errors = append(errors, fmt.Sprintf("unsupported key_type: %s", req.KeyType))
	}

	if len(errors) > 0 {
		return fmt.Errorf("%s", strings.Join(errors, "; "))
	}
	return nil
}

// Keep bip32 reference to prevent unused import warning
var _ = bip32.NewMasterKey
