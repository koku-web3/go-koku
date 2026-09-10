package securestore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"

	"github.com/koku-web3/go-koku/pkg/securestore/algorithm"
	"github.com/tyler-smith/go-bip32"
)

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
	// []byte(nil) 是 nil 切片
	// []byte{} 是长度为0的非nil切片
	secureBytes := append([]byte{}, keyBytes...)

	return &SecurePrivateKey{
		key:         key,
		keyBytes:    secureBytes,
		algorithmID: algorithmID,
	}
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

// Memzero 将字节切片清零
// 只能清零当前引用的内存，无法保证 GC 不会复制数据
// 但可以防止从同一切片访问时获取到敏感数据
func Memzero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// MemzeroBip32Key 安全清零 bip32.Key 中的所有敏感字段(Key/ChainCode/ChildNumber/FingerPrint/Version)。
// 清零后保留字段结构,但底层字节数组被置零。nil 安全,重复调用安全。
// 注意:此函数无法清零 GC 已回收的副本或 bip32 库内部深拷贝的字段。
func MemzeroBip32Key(k *bip32.Key) {
	if k == nil {
		return
	}
	Memzero(k.Key)
	Memzero(k.ChainCode)
	Memzero(k.ChildNumber)
	Memzero(k.FingerPrint)
	Memzero(k.Version)
}
