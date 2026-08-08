package securestore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/koku-web3/go-koku/internal/signer/securestore/algorithm"
)

// SecureBytes 安全字节切片，支持使用后自动清零
type SecureBytes struct {
	data []byte
}

// NewSecureBytes 从普通字节切片创建安全字节
func NewSecureBytes(data []byte) *SecureBytes {
	// 创建副本，避免原始数据被外部修改
	secure := &SecureBytes{
		data: append([]byte(nil), data...),
	}
	return secure
}

// Bytes 返回字节切片引用（调用方应尽快使用并调用 Clear）
func (sb *SecureBytes) Bytes() []byte {
	return sb.data
}

// Clear 将底层内存清零
func (sb *SecureBytes) Clear() {
	if sb.data != nil {
		for i := range sb.data {
			sb.data[i] = 0
		}
		sb.data = nil
	}
}

// SecureString 安全字符串，用于需要清零的字符串场景
type SecureString struct {
	chars []byte
}

// NewSecureString 从普通字符串创建安全字符串
func NewSecureString(s string) *SecureString {
	return &SecureString{
		chars: append([]byte(nil), s...),
	}
}

// String 返回字符串值（调用方应尽快使用并调用 Clear）
func (ss *SecureString) String() string {
	return string(ss.chars)
}

// Clear 将底层内存清零
func (ss *SecureString) Clear() {
	if ss.chars != nil {
		for i := range ss.chars {
			ss.chars[i] = 0
		}
		ss.chars = nil
	}
}

// Memzero 将字节切片清零
// 注意：Go 中这只能清零当前引用的内存，无法保证 GC 不会复制数据
// 但可以防止从同一切片访问时获取到敏感数据
func Memzero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// SecurePrivateKey 安全私钥包装器
// 用于在签名完成后自动清零私钥
type SecurePrivateKey struct {
	key         crypto.PrivateKey
	keyBytes    []byte // 原始 DER 字节，用于清零
	isCleared   bool
	algorithmID string // 关联的算法 ID，用于清零时调用正确的算法
}

// NewSecurePrivateKey 创建安全私钥包装器
func NewSecurePrivateKey(key crypto.PrivateKey, keyBytes []byte, algorithmID string) *SecurePrivateKey {
	// 创建 keyBytes 的安全副本
	secureBytes := append([]byte(nil), keyBytes...)
	return &SecurePrivateKey{
		key:         key,
		keyBytes:    secureBytes,
		algorithmID: algorithmID,
	}
}

// ParsePrivateKeyFromBase64 安全解析 base64 编码的 PEM 私钥
// 需要指定 algorithmID 以正确解析私钥
// 返回 SecurePrivateKey，使用后必须调用 Clear()
func ParsePrivateKeyFromBase64(base64Data string, algorithmID string) (*SecurePrivateKey, error) {
	pemBytes, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// 使用算法注册表解析私钥
	algo, err := algorithm.Get(algorithmID)
	if err != nil {
		return nil, fmt.Errorf("unsupported algorithm: %w", err)
	}

	key, err := algo.ParsePrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// 创建安全副本
	secureBytes := append([]byte(nil), block.Bytes...)

	return &SecurePrivateKey{
		key:         key,
		keyBytes:    secureBytes,
		algorithmID: algorithmID,
	}, nil
}

// Key 返回私钥接口
func (spk *SecurePrivateKey) Key() crypto.PrivateKey {
	return spk.key
}

// Clear 安全清零私钥相关的所有敏感内存
// 这是保护私钥安全的关键操作，必须在签名完成后调用
func (spk *SecurePrivateKey) Clear() {
	if spk.isCleared {
		return
	}

	// 清零内存中的私钥字节（序列化后的 DER 字节）
	if spk.keyBytes != nil {
		Memzero(spk.keyBytes)
	}

	// 如果有算法 ID，尝试使用算法注册表清零
	if spk.algorithmID != "" {
		if algo, err := algorithm.Get(spk.algorithmID); err == nil {
			algo.ClearPrivateKey(spk.key)
		}
	}

	// 备用清零逻辑：直接处理常见类型
	if spk.key != nil {
		switch key := spk.key.(type) {
		case *ecdsa.PrivateKey:
			// 清零 D 值（私钥标量）
			if key.D != nil {
				key.D.SetInt64(0)
			}
		case ed25519.PrivateKey:
			Memzero(key)
		case *ed25519.PrivateKey:
			Memzero(*key)
		}
	}

	spk.key = nil
	spk.isCleared = true
}

// IsCleared 检查私钥是否已被清零
func (spk *SecurePrivateKey) IsCleared() bool {
	return spk.isCleared
}

// SecureSigner 安全签名器包装器
// 在签名后自动清零私钥
type SecureSigner struct {
	privateKey *SecurePrivateKey
}

// NewSecureSigner 创建安全签名器
func NewSecureSigner(privateKey *SecurePrivateKey) *SecureSigner {
	return &SecureSigner{
		privateKey: privateKey,
	}
}

// Sign 执行签名并在完成后清零私钥
func (ss *SecureSigner) Sign(message []byte, hashFunc crypto.Hash) ([]byte, error) {
	defer ss.Clear() // 签名完成后立即清零

	signer, ok := ss.privateKey.Key().(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}

	return signer.Sign(rand.Reader, message, hashFunc)
}

// Clear 显式清零私钥
func (ss *SecureSigner) Clear() {
	if ss.privateKey != nil {
		ss.privateKey.Clear()
	}
}

// GenerateSecureRandom 生成安全随机字节
// 使用后应调用 Clear() 清零
func GenerateSecureRandom(length int) (*SecureBytes, error) {
	data := make([]byte, length)
	if _, err := rand.Read(data); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return NewSecureBytes(data), nil
}
