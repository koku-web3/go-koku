package algorithm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"math/big"
)

// Secp256r1 算法标识符, 又名 ecdsa-p256
const ESecp256r1 = "ecdsa-secp256r1"

// Secp256r1Algorithm secp256r1 (NIST P-256) 椭圆曲线 ECDSA 算法实现
type Secp256r1Algorithm struct {
	algorithmID string
}

// NewSecp256r1Algorithm 创建 Secp256r1 算法实例
func NewSecp256r1Algorithm() *Secp256r1Algorithm {
	return &Secp256r1Algorithm{
		algorithmID: ESecp256r1,
	}
}

// AlgorithmID 返回算法标识符
func (a *Secp256r1Algorithm) AlgorithmID() string {
	return a.algorithmID
}

// GenerateKey 生成 ECDSA 密钥对
func (a *Secp256r1Algorithm) GenerateKey() (crypto.PrivateKey, crypto.PublicKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}
	return priv, &priv.PublicKey, nil
}

// NewPrivateKeyFromBytes 从原始私钥字节创建 ECDSA 私钥对象
// 用于 BIP-32/BIP-44 派生子密钥的场景
func (a *Secp256r1Algorithm) NewPrivateKeyFromBytes(privKeyBytes []byte) (crypto.PrivateKey, error) {
	if len(privKeyBytes) != 32 {
		return nil, fmt.Errorf("invalid private key length: expected 32, got %d", len(privKeyBytes))
	}

	priv := new(ecdsa.PrivateKey)
	priv.Curve = elliptic.P256()
	priv.D = new(big.Int).SetBytes(privKeyBytes)
	priv.PublicKey.X, priv.PublicKey.Y = elliptic.P256().ScalarBaseMult(privKeyBytes)

	return priv, nil
}

// Sign 对消息进行 ECDSA 签名
func (a *Secp256r1Algorithm) Sign(privateKey crypto.PrivateKey, message []byte) ([]byte, error) {
	// 计算消息哈希
	h := sha256.Sum256(message)
	msgHash := h[:]

	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}

	signature, err := signer.Sign(rand.Reader, msgHash, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return signature, nil
}

// SerializePrivateKey 将 ECDSA 私钥序列化为 PKCS8 DER 格式
func (a *Secp256r1Algorithm) SerializePrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
	derBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	return derBytes, nil
}

// SerializePublicKey 将 ECDSA 公钥序列化为 PKIX 格式
func (a *Secp256r1Algorithm) SerializePublicKey(publicKey crypto.PublicKey) ([]byte, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	return pubBytes, nil
}

// ParsePrivateKey 解析 DER 格式的 ECDSA 私钥
func (a *Secp256r1Algorithm) ParsePrivateKey(derBytes []byte) (crypto.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(derBytes)
	if err != nil {
		key, err = x509.ParsePKCS1PrivateKey(derBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ECDSA private key: %w", err)
		}
	}
	return key, nil
}

// ClearPrivateKey 安全清零 ECDSA 私钥内存
func (a *Secp256r1Algorithm) ClearPrivateKey(privateKey crypto.PrivateKey) {
	if key, ok := privateKey.(*ecdsa.PrivateKey); ok {
		// 清零 D 值（私钥标量）
		if key.D != nil {
			key.D.SetInt64(0)
		}
		// 清零 X 和 Y（可选，因为公钥通常不需要清零）
		if key.X != nil {
			key.X.SetInt64(0)
		}
		if key.Y != nil {
			key.Y.SetInt64(0)
		}
	}
}

// HashFunc 返回签名使用的哈希函数
func (a *Secp256r1Algorithm) HashFunc() crypto.Hash {
	return crypto.SHA256
}

// init 注册 Secp256r1 算法
func init() {
	if err := Register(NewSecp256r1Algorithm()); err != nil {
		panic(fmt.Sprintf("warning: failed to register Secp256r1 curve: %v", err))
	}
}
