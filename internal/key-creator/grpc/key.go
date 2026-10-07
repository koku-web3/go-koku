package grpc

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"

	aead "github.com/koku-web3/go-koku/pkg/crypto"
	"github.com/koku-web3/go-koku/pkg/errors"
	"github.com/koku-web3/go-koku/pkg/hdwallet"
	"github.com/koku-web3/go-koku/pkg/keyutil"
	proto "github.com/koku-web3/go-koku/pkg/proto/key-creator"
	"github.com/koku-web3/go-koku/pkg/securestore"
	"github.com/koku-web3/go-koku/pkg/securestore/algorithm"
	"github.com/koku-web3/go-koku/pkg/vault/transit"
	log "github.com/koku-web3/logko"
	"github.com/tyler-smith/go-bip32"
)

// CreateOperationalKey 从指定 bip32.key 类型密钥派生子密钥
// 流程：
//  1. 对入参进行检查；
//  2. 从 {@link bip44Path} 判断派生密钥的用途（运营)；
//  3. 根据密钥类型获取对应的算法服务
//  4. 派生子密钥
func (s *KeyCreatorService) CreateOperationalKey(ctx context.Context, req *proto.CreateKeyRequest) (*proto.CreateKeyResponse, error) {
	return s.createDerivedKeys(req, keyutil.KEY_USAGE_OPERATIONAL, transit.OperationsTransit, transit.GetKeyNameForOperations)
}

// CreateUserKey 从指定 bip32.key 类型密钥派生子密钥
// 流程：
//  1. 对入参进行检查；
//  2. 从 {@link bip44Path} 判断派生密钥的用途（用户)；
//  3. 根据密钥类型获取对应的算法服务
//  4. 派生子密钥
func (s *KeyCreatorService) CreateUserKey(ctx context.Context, req *proto.CreateKeyRequest) (*proto.CreateKeyResponse, error) {
	return s.createDerivedKeys(req, keyutil.KEY_USAGE_USER, transit.UserTransit, transit.GetKeyNameForUser)
}

type keyNameFunc func(string) string

func (s *KeyCreatorService) createDerivedKeys(req *proto.CreateKeyRequest, expectedUsage keyutil.AccountUsage, transitName string, getKeyName keyNameFunc) (*proto.CreateKeyResponse, error) {
	if err := validateCreateKeyRequest(req); err != nil {
		log.Warn("Invalid input parameter", "trace_id", req.TraceId, "error", err)
		// err 只有字面量字符串，不包含任何敏感信息，可以直接返回给调用方
		return nil, errors.InvalidArgumentErr(err)
	}

	usage, err := findUsage(req.Bip44Path)
	if err != nil {
		log.Error("Resolve bip44_path failed", "trace_id", req.TraceId, "bip44_path", req.Bip44Path, "error", err)
		return nil, errors.InvalidArgument("bip44_path")
	}
	if usage != expectedUsage {
		log.Warn("Invalid bip44_path account", "trace_id", req.TraceId, "bip44_path", req.Bip44Path, "account", usage, "expected", expectedUsage)
		return nil, errors.InvalidArgument("bip44_path")
	}

	algo, err := algorithm.Get(req.KeyType)
	if err != nil {
		log.Error("Unsupported key type", "trace_id", req.TraceId, "key_type", req.KeyType, "error", err)
		return nil, errors.InvalidArgument("key_type")
	}

	res, err := s.deriveFifthDepthChildKeys(req, transitName, getKeyName(req.ChainCode), transit.Bip44PathToContext(req.Bip44Path), algo)
	if err != nil {
		log.Error("CreateKey failed", "trace_id", req.TraceId, "chain_code", req.ChainCode, "error", err)
		return nil, errors.Internal()
	}

	log.Info("CreateKey succeeded!", "trace_id", req.TraceId, "chain_code", req.ChainCode, "key_count", len(res.Keys))
	return res, nil
}

// generateThreeCoreKeys 创建指定区块链的 BIP-44 主密钥种子、以及派生它的两个密钥
// BIP-44 路径说明：m/purpose'/coinType'/account'/change/index
// 流程：
//  1. 生成随机 HD 主密钥种子 seed（32 字节）
//  2. 使用 seed 派生 m/44'/coinType'/0'/0/0（account=0，运营）路径的私钥
//  3. 使用 seed 派生 m/44'/coinType'/1'/0/0（account=1，用户）路径的私钥
//  4. 将两个 account 密钥分别序列化为字节
//  5. 使用 s.kmsServ.Encrypt 分别对 seed（master）和两个序列化密钥进行加密，
//     使用的 transit 引擎路径为 /transit/core
//  6. 返回 seed 密文、context、bip44Path 以及两个派生密钥的密文
//
// 安全要点：
//   - seed 包含主密钥的全部熵，必须在内存中显式擦除后方可释放；
//   - 所有 bip32.Key 明文通过各 defer 链路在函数返回前擦除；
//   - 各 Serialize() 中间字节片通过 defer Memzero 在函数返回前擦除；
//   - 加密后的 seed 可安全存储在数据库中；
//   - 对于密钥的操作，直接使用 bip32.Key 类型；需要对密钥加密时，使用 Serialize() 序列化；
//     需要解密时使用 NewMasterKey(seed) 从 seed 重建主密钥；
func (s *KeyCreatorService) generateThreeCoreKeys(chainCode string) (*proto.GenesisResponse, error) {
	// 验证链是否支持 BIP-44
	coinType, err := hdwallet.CoinTypeFromChainCode(chainCode)
	if err != nil {
		return nil, err
	}

	// ========== 步骤 1: 调用 vault 服务创建3把key ==========
	// 分别对应：
	//		   transit/core/{chainCode}-masterkey
	//		   transit/operations/{chainCode}-privkey
	//		   transit/user/{chainCode}-privkey
	if err := s.createVaultKeys(chainCode); err != nil {
		return nil, fmt.Errorf("call kMS to create 3 keys failed: %s", err.Error())
	}

	// ========== 步骤 2: 生成 HD 主密钥 seed ==========
	var (
		masterKey    *bip32.Key
		key44        *bip32.Key
		key44Coin    *bip32.Key
		keyAccount0  *bip32.Key
		keyAccount1  *bip32.Key
		seed         []byte
		opKeyBytes   []byte
		userKeyBytes []byte
	)

	masterKey, seed, err = hdwallet.GenerateBip32Key()
	if err != nil {
		return nil, err
	}

	// 所有 bip32.Key 明文和 seed 在函数退出时统一擦除（LIFO 顺序)
	defer func() {
		securestore.Memzero(seed)
		securestore.MemzeroBip32Key(keyAccount1)
		securestore.MemzeroBip32Key(keyAccount0)
		securestore.MemzeroBip32Key(key44Coin)
		securestore.MemzeroBip32Key(key44)
		securestore.MemzeroBip32Key(masterKey)
		securestore.Memzero(opKeyBytes)
		securestore.Memzero(userKeyBytes)
	}()

	// 派生 44' 密钥
	// m/44' — Purpose (hardened)
	key44, err = masterKey.NewChildKey(hdwallet.BIP44Purpose)
	if err != nil {
		return nil, fmt.Errorf("failed to derive m/44' — Purpose (hardened) key: %w", err)
	}

	// m/44'/0' — CoinType (hardened) 0=bitcoin; 60=ethereum;
	key44Coin, err = key44.NewChildKey(coinType)
	if err != nil {
		return nil, fmt.Errorf("failed to derive m/44'/0' — CoinType (hardened) key: %w", err)
	}

	// ========== 步骤 3: 派生运营账户私钥 ==========
	// m/44'/0'/0' — Account=0 (hardened)
	keyAccount0, err = key44Coin.NewChildKey(hdwallet.HardenedMark + hdwallet.AccountOperations)
	if err != nil {
		return nil, fmt.Errorf("failed to derive m/44'/0'/0' — Account=0 (hardened) key: %w", err)
	}

	// ========== 步骤 4: 派生用户账户私钥  ==========
	// m/44'/0'/1' — Account=1 (hardened)
	keyAccount1, err = key44Coin.NewChildKey(hdwallet.HardenedMark + hdwallet.AccountUser)
	if err != nil {
		return nil, fmt.Errorf("failed to derive m/44'/0'/1' — Account=1 (hardened) key: %w", err)
	}

	opKeyBytes, err = keyAccount0.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize keyAccount0: %w", err)
	}

	userKeyBytes, err = keyAccount1.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize keyAccount1: %w", err)
	}

	// ========== 步骤 5: 使用信封加密的方式 加密 seed 和两个派生密钥 (datakey + AES-GCM) ==========
	// 主密钥 seed
	mkBip44Path, err := hdwallet.MasterKeyPath(chainCode)
	if err != nil {
		return nil, fmt.Errorf("failed to generate %s master key path: %w", chainCode, err)
	}
	mkPathContext := transit.Bip44PathToContext(mkBip44Path)
	masterSeedCiphertext, masterSeedDEKCiphertext, err := s.encryptWithDataKey(transit.CoreTransit, transit.GetKeyNameForCore(chainCode), seed, mkPathContext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt masterKey's seed with data key: %w", err)
	}

	// 运营私钥
	opBip44Path, err := hdwallet.OperationsPath(chainCode)
	if err != nil {
		return nil, fmt.Errorf("failed to generate %s's operations-key path: %w", chainCode, err)
	}
	opPathContext := transit.Bip44PathToContext(opBip44Path)
	opCiphertext, opDEKCiphertext, err := s.encryptWithDataKey(transit.CoreTransit, transit.GetKeyNameForCore(chainCode), opKeyBytes, opPathContext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt operational's key with data key: %w", err)
	}

	// 用户私钥
	userBip44Path, err := hdwallet.UserPath(chainCode)
	if err != nil {
		return nil, fmt.Errorf("failed to generate %s's user-key path: %w", chainCode, err)
	}
	userPathContext := transit.Bip44PathToContext(userBip44Path)
	userCiphertext, userDEKCiphertext, err := s.encryptWithDataKey(transit.CoreTransit, transit.GetKeyNameForCore(chainCode), userKeyBytes, userPathContext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt user's key with data key: %w", err)
	}

	// ========== 步骤 6: 返回响应 ==========
	return &proto.GenesisResponse{
		SeedCiphertext: masterSeedCiphertext,
		DekCiphertext:  masterSeedDEKCiphertext,
		Context:        mkPathContext,
		Bip44Path:      mkBip44Path,
		DerivedKeys: []*proto.DerivedCoreKey{
			{
				KeyUsage:           keyutil.KEY_USAGE_OPERATIONAL.ToUin32(),
				Bip32KeyCiphertext: opCiphertext,
				DekCiphertext:      opDEKCiphertext,
				Context:            opPathContext,
				Bip44Path:          opBip44Path,
			},
			{
				KeyUsage:           keyutil.KEY_USAGE_USER.ToUin32(),
				Bip32KeyCiphertext: userCiphertext,
				DekCiphertext:      userDEKCiphertext,
				Context:            userPathContext,
				Bip44Path:          userBip44Path,
			},
		},
	}, nil
}

func (s *KeyCreatorService) createVaultKeys(chainCode string) error {
	err := s.kmsServ.CreateKey(transit.CoreTransit, transit.GetKeyNameForCore(chainCode), transit.DataEncryptionKeyType, true)
	if err != nil {
		return err
	}

	err = s.kmsServ.CreateKey(transit.OperationsTransit, transit.GetKeyNameForOperations(chainCode), transit.DataEncryptionKeyType, true)
	if err != nil {
		return err
	}

	err = s.kmsServ.CreateKey(transit.UserTransit, transit.GetKeyNameForUser(chainCode), transit.DataEncryptionKeyType, true)
	if err != nil {
		return err
	}
	return nil
}

// deriveFifthDepthChildKeys 从父密钥m/44'/60'/0' 或 m/44'/60'/1' 派生第五层（account_index）密钥
// 流程：
//  1. 使用 s.kmsServ.Decrypt 对父密钥的 DEK 数据（dek_ciphertext）进行解密
//  2. 使用已解密的 DEK 对父私钥（bip32_key_ciphertext）进行解密（aes256-gcm96)
//  3. 使用父密钥和 addrIdxStart 派生，得到 bip32.Key 类型的密钥
//  4. 将得到的新密钥转换为 DER 格式
//  5. 调用 vault 服务器（s.kmsServ.GenerateDataKey） 派生一个 data key 对已序列化为 DER 格式的密钥加密
//  6. 立即擦除所有明文私钥和 seed
//
// 安全要点：
//   - seed 包含主密钥的全部熵，必须在内存中显式擦除后方可释放；
//   - 私钥明文仅在 KeyCreatorService 内存中短暂存在；
//   - 对于 Vault 系统，不同的 transit 拥有较高的安全隔绝设计，将运营和用户的密钥区分开，能更好的
//     对权限进行控制。
func (s *KeyCreatorService) deriveFifthDepthChildKeys(req *proto.CreateKeyRequest, transitName, keyName, context string, algo algorithm.KeyAlgorithm) (*proto.CreateKeyResponse, error) {
	chainCode := req.ChainCode
	addrIdxStart := req.AccountIndexStart
	count := req.Count

	// dekPlaintext 是 string 类型，不可变且无法就地擦除。base64.StdEncoding.DecodeString 会申请新内存并复制数据，
	// 明文的最终二进制形态存储在 keyBytes 中（已通过 defer securestore.Memzero 保护）。
	// dekPlaintext 则依赖 GC 回收。
	dekPlaintext, err := s.kmsServ.Decrypt(transit.CoreTransit, transit.GetKeyNameForCore(chainCode), req.DekCiphertext, context)
	if err != nil {
		return nil, err
	}

	dekBytes, err := base64.StdEncoding.DecodeString(dekPlaintext)
	if err != nil {
		return nil, fmt.Errorf("decode DEK from base64 failed: %w", err)
	}
	defer securestore.Memzero(dekBytes)

	// 解密私钥信封
	// 私钥密文存入数据库时格式为： base64(nonce || encrypted)
	//
	// 其中
	// nonce（IV）：是对称加密 aes256-gcm 的随机数
	// encrypted：是 DER 格式的私钥密文
	envelopeBytes, err := base64.StdEncoding.DecodeString(req.Bip32KeyCiphertext)
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
		return nil, fmt.Errorf("failed to decode base64 string:%w", err)
	}
	// 清零私钥DER数据
	defer securestore.Memzero(privateDER)

	bip32AccountKey, err := bip32.Deserialize(privateDER)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize bip32 key: %w", err)
	}
	defer securestore.MemzeroBip32Key(bip32AccountKey)

	// 已解密出父密钥，开始进行派生
	// m/ 44'/ coinType'/ account'/ change （非强化）
	bip32Change, err := bip32AccountKey.NewChildKey(hdwallet.ChangeExternal)
	if err != nil {
		return nil, fmt.Errorf("failed to derive [change]'s childs: %w", err)
	}
	defer securestore.MemzeroBip32Key(bip32Change)

	keys := []*proto.DerivedChildKey{}
	end := addrIdxStart + count
	for i := addrIdxStart; i < end; i++ {
		key, err := s.derive(req.TraceId, bip32Change, i, algo, context, transitName, keyName)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}

	return &proto.CreateKeyResponse{Keys: keys}, nil
}

// derive 从指定父密钥派生单个密钥
func (s *KeyCreatorService) derive(traceID string, bip32Change *bip32.Key, accountIndex uint32, algo algorithm.KeyAlgorithm, context string, transitName string, keyName string) (*proto.DerivedChildKey, error) {
	childKey, err := bip32Change.NewChildKey(accountIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to derive child key at account_index %d: %w", accountIndex, err)
	}
	defer securestore.MemzeroBip32Key(childKey)

	privateKey, err := algo.NewPrivateKeyFromBytes(childKey.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap private key: %w", err)
	}

	securePrivateKey := securestore.NewSecurePrivateKey(privateKey, childKey.Key, algo.AlgorithmID())
	defer securePrivateKey.Clear()

	privateKeyDER, err := algo.SerializePrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize private key at account_index %d: %w", accountIndex, err)
	}
	defer securestore.Memzero(privateKeyDER)

	bip44Path := hdwallet.ChildPath(context, hdwallet.ChangeExternal, accountIndex)
	childContext := transit.Bip44PathToContext(bip44Path)
	ciphertext, dekCiphertext, err := s.encryptWithDataKey(transitName, keyName, privateKeyDER, childContext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt child key at bip44_path %s: %w", bip44Path, err)
	}

	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer at account_index %d", accountIndex)
	}
	publicKeyBytes, err := algo.SerializePublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to serialize public key at account_index %d: %w", accountIndex, err)
	}

	log.Info("Derive child key succeeded", "trace_id", traceID, "bip44_path", bip44Path, "account_index", accountIndex)

	return &proto.DerivedChildKey{
		AddressIndex:      accountIndex,
		PrivKeyCiphertext: ciphertext,
		DekCiphertext:     dekCiphertext,
		Context:           childContext,
		Bip44Path:         bip44Path,
		PublicKey:         encodePublicKeyToPEM(publicKeyBytes),
	}, nil
}

// findUsage 从 bip44 路径解析出 /{account}/ 层级的值
// {@linke bip44Path} 格式类似 m/44'/60'/0' 对应 m/purpose/coinType/account
// 解析 account 的值(0 或 1)
func findUsage(bip44Path string) (keyutil.AccountUsage, error) {
	parts := strings.Split(bip44Path, "/")
	if len(parts) < 4 {
		return keyutil.KEY_USAGE_UNKNOWN, fmt.Errorf("invalid bip44 path: %s", bip44Path)
	}
	// parts[3] 应该是 account，格式如 "0'" 或 "1'"
	accountPart := parts[3]
	accountStr := strings.TrimSuffix(accountPart, "'")
	accountUint64, err := strconv.ParseUint(accountStr, 10, 32)
	account := uint32(accountUint64)
	if err != nil {
		return keyutil.KEY_USAGE_UNKNOWN, fmt.Errorf("invalid account index in bip44 path: %s", bip44Path)
	}
	return keyutil.ToAccountUsage(account), nil
}

// validateCreateKeyRequest 校验 CreateKey 请求参数
func validateCreateKeyRequest(req *proto.CreateKeyRequest) error {
	var errors []string

	if req.TraceId == "" {
		errors = append(errors, "trace_id is required")
	}
	if req.ChainCode == "" || len(req.ChainCode) > 32 {
		errors = append(errors, "chain_code must be 1-32 characters")
	}
	if req.Bip44Path == "" || len(req.Bip44Path) > 32 {
		errors = append(errors, "bip44_path must be 1-32 characters")
	}
	if req.Bip32KeyCiphertext == "" {
		errors = append(errors, "bip32key_ciphertext is required")
	}
	if req.DekCiphertext == "" {
		errors = append(errors, "dek_ciphertext is required")
	}
	if req.Count == 0 || req.Count > 50 {
		errors = append(errors, "count must be 1-50")
	}

	if len(errors) > 0 {
		return fmt.Errorf("%s", strings.Join(errors, "; "))
	}
	return nil
}

// encodePublicKeyToPEM 将 PKIX 标准的公钥转化为 PEM 格式文本
func encodePublicKeyToPEM(pubBytes []byte) string {
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}
	return string(pem.EncodeToMemory(pemBlock))
}

// encryptWithDataKey 使用 datakey + AES-GCM 信封加密
// transitName: transit引擎名称
// keyName: 密钥名称
// plaintext: 待加密的明文
// context: 密钥派生上下文
// 返回: ciphertext (base64(nonce || encrypted)), dekCiphertext, 错误
func (s *KeyCreatorService) encryptWithDataKey(transitName, keyName string, plaintext []byte, context string) (string, string, error) {
	dekKey, err := s.kmsServ.GenerateDataKey(transitName, keyName, context)
	if err != nil {
		return "", "", fmt.Errorf("call kmsServ.GenerateData to generate data key failed: %w", err)
	}

	dekBytes, err := base64.StdEncoding.DecodeString(dekKey.Plaintext)
	if err != nil {
		return "", "", fmt.Errorf("decode DEK plaintext from base64 failed: %w", err)
	}
	defer securestore.Memzero(dekBytes)

	nonce, encrypted, err := aead.Encrypt(plaintext, dekBytes)
	if err != nil {
		return "", "", fmt.Errorf("AES-GCM encrypt failed: %w", err)
	}
	defer securestore.Memzero(encrypted)

	// 组合信封: base64(nonce || encrypted)
	envelope := make([]byte, len(nonce)+len(encrypted))
	copy(envelope, nonce)
	copy(envelope[len(nonce):], encrypted)

	ciphertext := base64.StdEncoding.EncodeToString(envelope)
	return ciphertext, dekKey.Ciphertext, nil
}
