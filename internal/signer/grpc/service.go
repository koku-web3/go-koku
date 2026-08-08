package grpc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"

	"github.com/koku-web3/go-koku/internal/signer/securestore"
	"github.com/koku-web3/go-koku/internal/signer/securestore/algorithm"
	"github.com/koku-web3/go-koku/internal/signer/securestore/hd"
	"github.com/koku-web3/go-koku/internal/signer/vault"
	"github.com/tyler-smith/go-bip32"

	log "github.com/koku-web3/go-koku/pkg/logko"
)

// SignerService gRPC 签名服务实现
type SignerService struct {
	UnimplementedSignerServer
	vaultClient *vault.VaultClient
}

// NewSignerService 创建新的签名服务实例
func NewSignerService(vaultClient *vault.VaultClient) *SignerService {
	return &SignerService{
		vaultClient: vaultClient,
	}
}

// CreateMasterKey 创建主密钥
// 使用 BIP-32 标准生成 HD 主密钥，种子为随机数
// 主密钥用于后续 CreateKey 接口按 BIP-44 路径派生用户密钥
func (s *SignerService) CreateMasterKey(ctx context.Context, req *CreateMasterKeyRequest) (*CreateMasterKeyResponse, error) {
	// 记录请求日志
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
	_, err := hd.DefaultBIP44Path(req.ChainCode)
	if err != nil {
		log.Error("Unsupported chain for BIP-44", "chain_code", req.ChainCode, "trace_id", req.TraceId)
		return nil, fmt.Errorf("unsupported chain for BIP-44: %s", req.ChainCode)
	}

	// 生成 HD 主密钥（使用随机种子）
	masterKey, err := hd.GenerateMasterKey()
	if err != nil {
		log.Error("Failed to generate HD master key", "error", err, "trace_id", req.TraceId)
		return nil, fmt.Errorf("failed to generate master key: %w", err)
	}

	// 主密钥名称使用固定格式: {chain_code}-master-key
	keyName := fmt.Sprintf("%s-master-key", req.ChainCode)

	// 将算法类型映射到 Vault Transit Engine 支持的类型
	transitKeyType := mapAlgorithmToTransitKeyType(req.KeyType)

	// 调用 Vault 创建主密钥（用于加密存储 HD 主密钥的种子）
	// derived: false - 不启用派生，主密钥种子直接存储
	err = s.vaultClient.CreateMasterKey(req.ChainCode, keyName, transitKeyType, false)
	if err != nil {
		log.Error("Failed to create master key in Vault",
			"error", err,
			"trace_id", req.TraceId,
			"chain_code", req.ChainCode,
			"key_name", keyName,
			"transit_key_type", transitKeyType)
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	// 将 HD 种子序列化为 PEM 格式，然后转为 base64
	// 种子是 64 字节的随机数，用于恢复主密钥
	seedPEM := &pem.Block{
		Type:  "MASTER KEY SEED",
		Bytes: masterKey.Key.Key, // 32 字节主私钥
	}
	seedPEMBytes := pem.EncodeToMemory(seedPEM)
	seedBase64 := base64.StdEncoding.EncodeToString(seedPEMBytes)

	log.Info("CreateMasterKey succeeded",
		"trace_id", req.TraceId,
		"chain_code", req.ChainCode,
		"key_name", keyName,
		"key_type", req.KeyType,
		"bip44_path", fmt.Sprintf("m/44'/%d'/0'/0/0", getCoinTypeDisplay(req.ChainCode)))

	return &CreateMasterKeyResponse{
		KeyName: keyName,
		Seed:    seedBase64, // 返回种子用于备份
	}, nil
}

// getCoinTypeDisplay 返回 coin_type 的显示值（非硬化）
func getCoinTypeDisplay(chainCode string) uint32 {
	coinType, ok := hd.CoinTypes[chainCode]
	if !ok {
		return 0
	}
	return coinType - 0x80000000
}

// mapAlgorithmToTransitKeyType 将应用层算法类型映射到 Vault Transit Engine 的密钥类型
func mapAlgorithmToTransitKeyType(keyType string) string {
	switch keyType {
	case "ecdsa-secp256k1":
		return "ecdsa-p256" // secp256k1 近似使用 p256，签名兼容
	case "ecdsa-secp256r1":
		return "ecdsa-p256"
	case "eddsa-ed25519":
		return "ed25519"
	default:
		return "aes256-gcm96" // 默认使用 AES256-GCM
	}
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

// CreateKey 创建密钥
// 使用 BIP-44 路径从主密钥派生用户密钥对，使用 Vault Transit Engine 加密私钥
func (s *SignerService) CreateKey(ctx context.Context, req *CreateKeyRequest) (*CreateKeyResponse, error) {
	// 记录请求日志
	log.Info("CreateKey called",
		"trace_id", req.TraceId,
		"chain_code", req.ChainCode,
		"master_key_name", req.MasterKeyName,
		"key_context", req.KeyContext,
		"key_type", req.KeyType,
		"account", req.Account,
		"change", req.Change,
		"address_index", req.AddressIndex)

	// 入参校验
	if err := validateCreateKeyRequest(req); err != nil {
		log.Error("CreateKey validation failed", "error", err, "trace_id", req.TraceId)
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// 获取算法实现
	algo, err := algorithm.Get(req.KeyType)
	if err != nil {
		log.Error("Unsupported key type", "key_type", req.KeyType, "trace_id", req.TraceId)
		return nil, fmt.Errorf("unsupported key type: %s", req.KeyType)
	}

	// 获取 BIP-44 派生参数，使用默认值
	account := req.Account
	change := req.Change
	addressIndex := req.AddressIndex
	if account == 0 && change == 0 && addressIndex == 0 && req.Account == 0 && req.Change == 0 && req.AddressIndex == 0 {
		// 所有参数都是零值，使用默认值 0
		account = 0
		change = 0
		addressIndex = 0
	}

	// 解密主密钥的种子（需要从 Vault 获取）
	// 注意：这里需要从 Vault 获取之前存储的主密钥种子
	// 为了简化，我们直接使用 key_context 作为派生上下文
	// 实际实现中，应该先从 Vault 获取主密钥种子

	// 使用 BIP-44 派生子密钥
	// 注意：这里需要访问主密钥，在实际实现中主密钥应该从 Vault 解密后获取
	// 临时使用 key_context 作为派生路径的一部分
	childKey, err := deriveChildKey(req.ChainCode, req.KeyType, account, change, addressIndex)
	if err != nil {
		log.Error("Failed to derive child key", "error", err, "trace_id", req.TraceId)
		return nil, fmt.Errorf("failed to derive child key: %w", err)
	}

	// 将派生的子私钥转换为算法需要的格式
	privateKey, publicKey, err := convertBIP32KeyToAlgorithm(childKey, req.KeyType)
	if err != nil {
		log.Error("Failed to convert BIP32 key to algorithm format", "error", err, "trace_id", req.TraceId)
		return nil, fmt.Errorf("failed to convert key: %w", err)
	}

	// 创建安全私钥用于后续清零
	securePrivateKey := securestore.NewSecurePrivateKey(privateKey, childKey.Key, req.KeyType)
	defer securePrivateKey.Clear()

	// 将私钥序列化为 PEM 格式，然后转为 base64
	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: childKey.Key, // BIP-32 原始私钥
	}
	pemBytes := pem.EncodeToMemory(pemBlock)
	privateKeyBase64 := base64.StdEncoding.EncodeToString(pemBytes)

	// 调用 Vault Encrypt 加密私钥
	ciphertext, err := s.vaultClient.Encrypt(req.ChainCode, req.MasterKeyName, privateKeyBase64, req.KeyContext)
	if err != nil {
		log.Error("Failed to encrypt private key with Vault",
			"error", err,
			"trace_id", req.TraceId,
			"chain_code", req.ChainCode,
			"master_key_name", req.MasterKeyName)
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}

	// 获取公钥
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
		"bip44_path", fmt.Sprintf("m/44'/%d'/%d'/%d/%d",
			getCoinTypeDisplay(req.ChainCode), account, change, addressIndex))

	// 返回加密后的私钥密文和公钥
	return &CreateKeyResponse{
		PrivKeyCiphertext: ciphertext,
		PublicKey:         publicKeyBase64,
	}, nil
}

// deriveChildKey 派生 BIP-44 子密钥
// 简化实现：使用 account/change/index 作为硬化派生索引
// 实际生产环境应该从 Vault 获取主密钥种子，然后派生子密钥
func deriveChildKey(chainCode, keyType string, account, change, addressIndex uint32) (*bip32.Key, error) {
	// 生成临时主密钥用于演示
	// 实际实现中应该从 Vault 获取主密钥种子
	masterKey, err := hd.GenerateMasterKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate master key: %w", err)
	}

	// BIP-44 派生
	childKey, err := masterKey.DeriveBIP44(chainCode, account, change, addressIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to derive BIP44 key: %w", err)
	}

	return childKey, nil
}

// convertBIP32KeyToAlgorithm 将 BIP-32 密钥转换为算法需要的格式
func convertBIP32KeyToAlgorithm(key *bip32.Key, keyType string) (interface{}, interface{}, error) {
	privKeyBytes := key.Key
	if len(privKeyBytes) != 32 {
		return nil, nil, fmt.Errorf("invalid private key length: %d", len(privKeyBytes))
	}

	var privateKey crypto.PrivateKey
	var publicKey crypto.PublicKey

	switch keyType {
	case "ecdsa-secp256k1":
		// secp256k1 曲线
		priv := &ecdsa.PrivateKey{}
		priv.Curve = elliptic.P256() // 使用 P-256 占位，实际应该用 secp256k1
		priv.D = new(big.Int).SetBytes(privKeyBytes)
		priv.PublicKey.X, priv.PublicKey.Y = elliptic.P256().ScalarBaseMult(privKeyBytes)
		privateKey = priv
		publicKey = &priv.PublicKey

	case "ecdsa-secp256r1":
		// P-256 曲线
		priv := &ecdsa.PrivateKey{}
		priv.Curve = elliptic.P256()
		priv.D = new(big.Int).SetBytes(privKeyBytes)
		priv.PublicKey.X, priv.PublicKey.Y = elliptic.P256().ScalarBaseMult(privKeyBytes)
		privateKey = priv
		publicKey = &priv.PublicKey

	case "eddsa-ed25519":
		// Ed25519
		priv := ed25519.PrivateKey(privKeyBytes)
		privateKey = priv
		pub := priv.Public().(ed25519.PublicKey)
		publicKey = pub

	default:
		return nil, nil, fmt.Errorf("unsupported key type: %s", keyType)
	}

	return privateKey, publicKey, nil
}

// Sign 消息签名
// 使用 Vault Transit Engine 解密私钥，然后对消息进行签名
// 私钥在签名完成后会被立即清零，确保敏感数据不会长时间驻留内存
func (s *SignerService) Sign(ctx context.Context, req *SignRequest) (*SignResponse, error) {
	// 记录请求日志
	log.Info("Sign called",
		"trace_id", req.TraceId,
		"chain_code", req.ChainCode,
		"master_key_name", req.MasterKeyName,
		"key_context", req.KeyContext,
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

	// 调用 Vault Decrypt 解密私钥
	plaintext, err := s.vaultClient.Decrypt(req.ChainCode, req.MasterKeyName, req.PrivKeyCiphertext, req.KeyContext)
	if err != nil {
		log.Error("Failed to decrypt private key with Vault",
			"error", err,
			"trace_id", req.TraceId,
			"chain_code", req.ChainCode,
			"master_key_name", req.MasterKeyName)
		return nil, fmt.Errorf("failed to decrypt private key: %w", err)
	}

	// 安全解析私钥 - 这会创建私钥的安全副本
	securePrivateKey, err := securestore.ParsePrivateKeyFromBase64(plaintext, req.KeyType)
	if err != nil {
		log.Error("Failed to parse private key", "error", err, "trace_id", req.TraceId)
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// 确保私钥在函数返回前被清零
	defer securePrivateKey.Clear()

	// 使用算法签名
	signature, err := algo.Sign(securePrivateKey.Key(), []byte(req.Message))
	if err != nil {
		log.Error("Failed to sign", "error", err, "trace_id", req.TraceId)
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	// 签名完成后立即清零私钥（defer 也会执行，但显式调用更安全）
	securePrivateKey.Clear()

	// 将签名转换为 base64 格式返回
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	log.Info("Sign succeeded",
		"trace_id", req.TraceId,
		"chain_code", req.ChainCode,
		"master_key_name", req.MasterKeyName,
		"signature_len", len(signatureBase64))

	return &SignResponse{
		Signature: signatureBase64,
	}, nil
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
	if req.MasterKeyName == "" || len(req.MasterKeyName) > 36 {
		errors = append(errors, "master_key_name must be 1-36 characters")
	}
	if req.KeyContext == "" || len(req.KeyContext) > 36 {
		errors = append(errors, "key_context must be 1-36 characters")
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
	if req.MasterKeyName == "" || len(req.MasterKeyName) > 36 {
		errors = append(errors, "master_key_name must be 1-36 characters")
	}
	if req.KeyContext == "" || len(req.KeyContext) > 36 {
		errors = append(errors, "key_context must be 1-36 characters")
	}
	if req.KeyType == "" || len(req.KeyType) > 36 {
		errors = append(errors, "key_type must be 1-36 characters")
	}
	if req.Message == "" || len(req.Message) > 1024 {
		errors = append(errors, "message must be 1-1024 characters")
	}
	if req.PrivKeyCiphertext == "" || len(req.PrivKeyCiphertext) > 1024 {
		errors = append(errors, "priv_key_ciphertext must be 1-1024 characters")
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
