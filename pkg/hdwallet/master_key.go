// Package hdwallet 实现了 HD 钱包密钥派生功能 (BIP-32)
// 参考: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
package hdwallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/tyler-smith/go-bip32"

	"github.com/koku-web3/go-koku/pkg/bip44"
)

const (
	// TypeMasterKeySeed 是主密钥种子的 PEM 类型标识
	TypeMasterKeySeed = "MASTER KEY SEED"
)

// MasterKey 代表一个 HD 主密钥
type MasterKey struct {
	Key       *bip32.Key // BIP-32 密钥
	ChainCode []byte     // 链码
}

// GenerateMasterKey 生成一个新的 HD 主密钥
// 使用 cryptographically secure random 作为种子
func GenerateMasterKey() (*MasterKey, error) {
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("failed to generate random seed: %w", err)
	}
	return NewMasterKeyFromSeed(seed)
}

// NewMasterKeyFromSeed 从种子创建主密钥
func NewMasterKeyFromSeed(seed []byte) (*MasterKey, error) {
	if len(seed) < 16 || len(seed) > 64 {
		return nil, fmt.Errorf("seed length must be between 16 and 64 bytes")
	}

	// BIP-32: 主密钥生成使用 HMAC-SHA512
	// key = "Bitcoin seed"
	hmac := hmacSHA512([]byte("Bitcoin seed"), seed)

	key, err := bip32.NewMasterKey(hmac[:32])
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	return &MasterKey{
		Key:       key,
		ChainCode: hmac[32:],
	}, nil
}

// Derive 根据 BIP-44 路径派生密钥
func (mk *MasterKey) Derive(path *bip44.BIP44Path) (*bip32.Key, error) {
	derivedKey := mk.Key
	hardenedPath := path.ToHardenedPath()

	for _, index := range hardenedPath {
		var err error
		derivedKey, err = derivedKey.NewChildKey(index)
		if err != nil {
			return nil, fmt.Errorf("failed to derive at index %d: %w", index, err)
		}
	}

	return derivedKey, nil
}

// DeriveFromChainCode 派生子密钥使用 BIP-44 路径
// chainCode: 链名称 (如 "ethereum", "bitcoin")
// account: 账户索引
// change: 0=外部链, 1=内部链
// index: 地址索引
func (mk *MasterKey) DeriveFromChainCode(chainCode string, account, change, index uint32) (*bip32.Key, error) {
	coinType, err := bip44.CoinTypeFromChainCode(chainCode)
	if err != nil {
		return nil, err
	}

	path := &bip44.BIP44Path{
		Purpose:      0x8000002C, // 44'
		CoinType:     0x80000000 + coinType,
		Account:      0x80000000 + account,
		Change:       change,
		AddressIndex: index,
	}

	return mk.Derive(path)
}

// DeriveChild 派生子密钥
func (mk *MasterKey) DeriveChild(index uint32) (*bip32.Key, error) {
	child, err := mk.Key.NewChildKey(index)
	if err != nil {
		return nil, fmt.Errorf("failed to derive child key: %w", err)
	}
	return child, nil
}

// DeriveECDSA 返回私钥的 ECDSA (P-256) 表示
func (mk *MasterKey) DeriveECDSA() (*ecdsa.PrivateKey, error) {
	privKeyBytes := mk.Key.Key
	if len(privKeyBytes) != 32 {
		return nil, fmt.Errorf("invalid private key length: %d", len(privKeyBytes))
	}

	priv := &ecdsa.PrivateKey{}
	priv.Curve = elliptic.P256()
	priv.D = new(big.Int).SetBytes(privKeyBytes)
	priv.PublicKey.X, priv.PublicKey.Y = elliptic.P256().ScalarBaseMult(privKeyBytes)

	return priv, nil
}

// DeriveSecp256k1 返回私钥的 secp256k1 表示
func (mk *MasterKey) DeriveSecp256k1() (*secp256k1.PrivateKey, error) {
	privKeyBytes := mk.Key.Key
	if len(privKeyBytes) != 32 {
		return nil, fmt.Errorf("invalid private key length: %d", len(privKeyBytes))
	}
	return secp256k1.PrivKeyFromBytes(privKeyBytes), nil
}

// PublicKey 返回公钥字节
func (mk *MasterKey) PublicKey() []byte {
	return mk.Key.PublicKey().Key
}

// EncodeMasterKeySeed 将 HD 主密钥种子编码为 base64 PEM 格式
// 返回 base64 编码的字符串，可用于 Vault 加密存储
func EncodeMasterKeySeed(masterKey *MasterKey) (string, error) {
	pemBlock := &pem.Block{
		Type:  TypeMasterKeySeed,
		Bytes: masterKey.Key.Key,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)
	return base64.StdEncoding.EncodeToString(pemBytes), nil
}

// DecodeMasterKeySeed 从 base64 PEM 解码并恢复 HD 主密钥
// 用于 CreateKey 时解密并恢复主密钥
func DecodeMasterKeySeed(base64PEM string) (*MasterKey, error) {
	// Base64 解码
	pemBytes, err := base64.StdEncoding.DecodeString(base64PEM)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 PEM: %w", err)
	}

	// PEM 解码
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// 验证 PEM 类型
	if block.Type != TypeMasterKeySeed {
		return nil, fmt.Errorf("invalid PEM type: %s, expected %s", block.Type, TypeMasterKeySeed)
	}

	// 从种子创建主密钥
	return NewMasterKeyFromSeed(block.Bytes)
}

// EncodePrivateKey 将私钥字节编码为 PEM 格式
func EncodePrivateKey(keyBytes []byte, blockType string) ([]byte, error) {
	pemBlock := &pem.Block{
		Type:  blockType,
		Bytes: keyBytes,
	}
	return pem.EncodeToMemory(pemBlock), nil
}

// DecodePEM 解码 PEM 块
// 返回解码后的块和剩余未解码的数据
func DecodePEM(data []byte) (*pem.Block, []byte) {
	return pem.Decode(data)
}

// hmacSHA512 计算 HMAC-SHA512
func hmacSHA512(key, data []byte) []byte {
	h := sha512.New()
	h.Write(key)
	h.Write(data)
	return h.Sum(nil)
}
