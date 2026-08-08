package algorithm

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
)

// Ed25519Algorithm Ed25519 算法实现
type Ed25519Algorithm struct{}

// NewEd25519Algorithm 创建 Ed25519 算法实例
func NewEd25519Algorithm() *Ed25519Algorithm {
	return &Ed25519Algorithm{}
}

// AlgorithmID 返回算法标识符
func (a *Ed25519Algorithm) AlgorithmID() string {
	return "eddsa-ed25519"
}

// GenerateKey 生成 Ed25519 密钥对
func (a *Ed25519Algorithm) GenerateKey() (crypto.PrivateKey, crypto.PublicKey, error) {
	// Ed25519 密钥生成
	// 生成随机种子 (32字节)
	seed := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, nil, fmt.Errorf("failed to read random bytes: %w", err)
	}

	// 使用种子生成 Ed25519 密钥对
	pub, priv, err := ed25519.GenerateKey(bytes.NewReader(seed))
	if err != nil {
		memzero(seed)
		return nil, nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}

	// 清零种子（不再需要）
	memzero(seed)

	return priv, pub, nil
}

// Sign 对消息进行 Ed25519 签名
func (a *Ed25519Algorithm) Sign(privateKey crypto.PrivateKey, message []byte) ([]byte, error) {
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}

	// Ed25519 签名: crypto.Hash(0) 表示不需要额外哈希，Ed25519 内部使用 SHA-512
	signature, err := signer.Sign(rand.Reader, message, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return signature, nil
}

// SerializePrivateKey 将 Ed25519 私钥序列化为 PKCS8 DER 格式
func (a *Ed25519Algorithm) SerializePrivateKey(privateKey crypto.PrivateKey) ([]byte, error) {
	derBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	return derBytes, nil
}

// SerializePublicKey 将 Ed25519 公钥序列化为 PKIX 格式
func (a *Ed25519Algorithm) SerializePublicKey(publicKey crypto.PublicKey) ([]byte, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	return pubBytes, nil
}

// ParsePrivateKey 解析 DER 格式的 Ed25519 私钥
func (a *Ed25519Algorithm) ParsePrivateKey(derBytes []byte) (crypto.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Ed25519 private key: %w", err)
	}
	return key, nil
}

// ClearPrivateKey 安全清零 Ed25519 私钥内存
func (a *Ed25519Algorithm) ClearPrivateKey(privateKey crypto.PrivateKey) {
	switch key := privateKey.(type) {
	case ed25519.PrivateKey:
		memzero(key)
	case *ed25519.PrivateKey:
		memzero(*key)
	}
}

// HashFunc 返回签名使用的哈希函数
// Ed25519 内部使用 SHA-512，返回 0 表示不需要外部哈希
func (a *Ed25519Algorithm) HashFunc() crypto.Hash {
	return crypto.Hash(0)
}

// memzero 将字节切片清零
func memzero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// init 注册 Ed25519 算法
func init() {
	if err := Register(NewEd25519Algorithm()); err != nil {
		panic(fmt.Sprintf("warning: failed to register edd25519 curve: %v", err))
	}
}
