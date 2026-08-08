package algorithm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
)

// ECDSAAlgorithm ECDSA 算法实现
// 支持 P-256 和 secp256k1 曲线
type ECDSAAlgorithm struct {
	curve       elliptic.Curve
	algorithmID string
}

// NewECDSAAlgorithm 创建 ECDSA 算法实例
func NewECDSAAlgorithm(algorithmID string, curve elliptic.Curve) *ECDSAAlgorithm {
	return &ECDSAAlgorithm{
		curve:       curve,
		algorithmID: algorithmID,
	}
}

// AlgorithmID 返回算法标识符
func (a *ECDSAAlgorithm) AlgorithmID() string {
	return a.algorithmID
}

// GenerateKey 生成 ECDSA 密钥对
func (a *ECDSAAlgorithm) GenerateKey() (crypto.PrivateKey, crypto.PublicKey, error) {
	priv, err := ecdsa.GenerateKey(a.curve, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}
	return priv, &priv.PublicKey, nil
}

// Sign 对消息进行 ECDSA 签名
func (a *ECDSAAlgorithm) Sign(privateKey crypto.PrivateKey, message []byte) ([]byte, error) {
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
func (a *ECDSAAlgorithm) SerializePrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
	derBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	return derBytes, nil
}

// SerializePublicKey 将 ECDSA 公钥序列化为 PKIX 格式
func (a *ECDSAAlgorithm) SerializePublicKey(publicKey crypto.PublicKey) ([]byte, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	return pubBytes, nil
}

// ParsePrivateKey 解析 DER 格式的 ECDSA 私钥
func (a *ECDSAAlgorithm) ParsePrivateKey(derBytes []byte) (crypto.PrivateKey, error) {
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
func (a *ECDSAAlgorithm) ClearPrivateKey(privateKey crypto.PrivateKey) {
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
func (a *ECDSAAlgorithm) HashFunc() crypto.Hash {
	return crypto.SHA256
}

// init 注册 ECDSA 算法
func init() {
	// 注册 secp256k1 (注意: Go 标准库不包含 secp256k1，使用 P-256 作为占位)
	// 实际生产环境应使用第三方库如 github.com/decred/dcrd/dcrec/secp256k1/v4
	if err := Register(NewECDSAAlgorithm("ecdsa-secp256k1", elliptic.P256())); err != nil {
		panic(fmt.Sprintf("warning: failed to register secp256k1 curve: %v", err))
	}

	// 注册 secp256r1 (P-256)
	if err := Register(NewECDSAAlgorithm("ecdsa-secp256r1", elliptic.P256())); err != nil {
		panic(fmt.Sprintf("warning: failed to register secp256r1 curve: %v", err))
	}
}

// SECP256K1Curve secp256k1 椭圆曲线（需要第三方库支持）
// 如需完整支持 secp256k1，可使用 github.com/decred/dcrd/dcrec/secp256k1/v4
var SECP256K1Curve = elliptic.P256() // 占位符，实际应使用 secp256k1 曲线

// SetSECP256K1Curve 设置 secp256k1 曲线实现
// 可以在运行时替换为真正的 secp256k1 实现
func SetSECP256K1Curve(curve elliptic.Curve) {
	// 更新 secp256k1 算法使用的曲线
	if err := Register(NewECDSAAlgorithm("ecdsa-secp256k1", curve)); err != nil {
		panic(fmt.Sprintf("warning: failed to update secp256k1 curve: %v", err))
	}
}
