package algorithm

import (
	"crypto"
	"fmt"
	"sync"
)

// KeyAlgorithm 密钥算法接口
// 所有支持的签名算法都需要实现此接口
type KeyAlgorithm interface {
	// AlgorithmID 返回算法标识符，如 "ecdsa-secp256k1", "ecdsa-secp256r1", "eddsa-ed25519"
	AlgorithmID() string

	// GenerateKey 生成密钥对
	GenerateKey() (crypto.PrivateKey, crypto.PublicKey, error)

	// NewPrivateKeyFromBytes 从原始私钥字节创建私钥对象
	// 用于 BIP-32/BIP-44 派生子密钥的场景
	NewPrivateKeyFromBytes(privKeyBytes []byte) (crypto.PrivateKey, error)

	// Sign 对消息进行签名
	Sign(privateKey crypto.PrivateKey, message []byte) ([]byte, error)

	// SerializePrivateKey 将私钥序列化为 DER 字节
	// DER: Distinguished Encoding Rules，抽象语法记法的一种二进制编码格式，常用于加密标准如 PKCS#8/PKCS#1
	SerializePrivateKey(privateKey crypto.PrivateKey) ([]byte, error)

	// SerializePublicKey 将公钥序列化为 PKIX 字节
	// PKIX：Public Key Infrastructure (X.509) 是 X.509 公钥基础设施标准，常用于描述和序列化公钥（如 SubjectPublicKeyInfo 结构）。
	// 在加密和证书体系中，PKIX 格式用于标准化不同算法的公钥编码，方便导入导出和互操作。
	SerializePublicKey(publicKey crypto.PublicKey) ([]byte, error)

	// ParsePrivateKey 解析 DER 格式的私钥
	ParsePrivateKey(derBytes []byte) (crypto.PrivateKey, error)

	// ClearPrivateKey 安全清零私钥内存
	ClearPrivateKey(privateKey crypto.PrivateKey)

	// HashFunc 返回签名使用的哈希函数
	HashFunc() crypto.Hash
}

// algorithmRegistry 算法注册表
type algorithmRegistry struct {
	sync.RWMutex
	algorithms map[string]KeyAlgorithm
}

// 全局算法注册表实例
var globalRegistry = &algorithmRegistry{
	algorithms: make(map[string]KeyAlgorithm),
}

// Register 注册算法实现
// 如果算法已存在会覆盖
func Register(algo KeyAlgorithm) error {
	if algo == nil {
		return fmt.Errorf("cannot register nil algorithm")
	}
	id := algo.AlgorithmID()
	if id == "" {
		return fmt.Errorf("algorithm id cannot be empty")
	}

	globalRegistry.Lock()
	defer globalRegistry.Unlock()

	globalRegistry.algorithms[id] = algo
	return nil
}

// Get 获取算法实现
func Get(algorithmID string) (KeyAlgorithm, error) {
	globalRegistry.RLock()
	defer globalRegistry.RUnlock()

	algo, ok := globalRegistry.algorithms[algorithmID]
	if !ok {
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithmID)
	}
	return algo, nil
}

// GetAll 获取所有已注册的算法
func GetAll() map[string]KeyAlgorithm {
	globalRegistry.RLock()
	defer globalRegistry.RUnlock()

	result := make(map[string]KeyAlgorithm, len(globalRegistry.algorithms))
	for k, v := range globalRegistry.algorithms {
		result[k] = v
	}
	return result
}

// IsSupported 检查算法是否支持
func IsSupported(algorithmID string) bool {
	_, err := Get(algorithmID)
	return err == nil
}
