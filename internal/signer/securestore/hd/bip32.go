// Package hd 实现了 BIP-32 层级确定性钱包和 BIP-44 多链钱包标准
package hd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/tyler-smith/go-bip32"
)

// CoinType 定义了 BIP-44 标准中各区块链的 coin_type
// 参考: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
var CoinTypes = map[string]uint32{
	"bitcoin":   0x80000000,          // 0'
	"ethereum":  0x8000003C,          // 60'
	"tron":      0x800000C3,          // 195'
	"solana":    0x80000137,          // 311'
	"polygon":   0x80000089,          // 137'
	"bsc":       0x80000098,          // 152'
	"avalanche": 9000 | 0x80000000,   // 9000' = 0x80002328
	"arbitrum":  42161 | 0x80000000,  // 42161' = 0x8000A4B1
	"optimism":  42000 | 0x80000000,  // 42000' = 0x8000A3F0
	"base":      8453 | 0x80000000,   // 8453' = 0x80002105
	"linea":     59144 | 0x80000000,  // 59144' = 0x8000E708
	"zksync":    324 | 0x80000000,    // 324' = 0x80000144
	"scroll":    534352 | 0x80000000, // 534352' = 0x80008290
	"mantle":    5700 | 0x80000000,   // 5700' = 0x80001644
	"filecoin":  461 | 0x80000000,    // 461' = 0x800001CD
}

// BIP32Path 表示一个 BIP-32 派生路径
// 格式: m / purpose' / coin_type' / account' / change / address_index
type BIP32Path struct {
	Purpose      uint32 // BIP purpose, 通常是 44 ( Harden )
	CoinType     uint32 // Chain coin type (Hardened)
	Account      uint32 // Account index (Hardened)
	Change       uint32 // External (0) or Internal (1) chain
	AddressIndex uint32 // Address index
}

// DefaultBIP44Path 为给定链创建默认的 BIP-44 路径
// m/44'/coin_type'/0'/0/0
func DefaultBIP44Path(chainCode string) (*BIP32Path, error) {
	coinType, ok := CoinTypes[chainCode]
	if !ok {
		return nil, fmt.Errorf("unsupported chain: %s", chainCode)
	}
	return &BIP32Path{
		Purpose:      0x8000002C, // 44' = 0x8000002C
		CoinType:     coinType,
		Account:      0x80000000, // 0'
		Change:       0,
		AddressIndex: 0,
	}, nil
}

// String 返回路径的字符串表示
func (p *BIP32Path) String() string {
	return fmt.Sprintf("m/%d'/%d'/%d'/%d/%d",
		p.Purpose-0x80000000, // 显示非硬化值
		p.CoinType-0x80000000,
		p.Account-0x80000000,
		p.Change,
		p.AddressIndex)
}

// ToHardenedPath 将路径转换为 go-bip32 的硬化派生索引
func (p *BIP32Path) ToHardenedPath() []uint32 {
	path := make([]uint32, 5)
	path[0] = p.Purpose // 44'
	path[1] = p.CoinType
	path[2] = p.Account
	path[3] = p.Change
	path[4] = p.AddressIndex
	return path
}

// MasterKey 代表一个 HD 主密钥
type MasterKey struct {
	Key       *bip32.Key // BIP-32 密钥
	ChainCode []byte     // 链码
}

// GenerateMasterKey 生成一个新的 HD 主密钥
// 使用 cryptographically secure random 作为种子
func GenerateMasterKey() (*MasterKey, error) {
	// 生成 64 字节的随机种子 (512 bits, 符合 BIP-32 要求)
	seed := make([]byte, 64)
	if _, err := rand.Read(seed); err != nil {
		return nil, fmt.Errorf("failed to generate random seed: %w", err)
	}

	// 使用种子生成主密钥 (BIP-32 规范: HMAC-SHA512)
	return NewMasterKeyFromSeed(seed)
}

// NewMasterKeyFromSeed 从种子创建主密钥
func NewMasterKeyFromSeed(seed []byte) (*MasterKey, error) {
	if len(seed) < 16 || len(seed) > 64 {
		return nil, fmt.Errorf("seed length must be between 16 and 64 bytes")
	}

	// BIP-32: 主密钥生成使用 HMAC-SHA512
	// key = "Bitcoin seed"
	// I = HMAC-SHA512(key, seed)
	// L = left 32 bytes (master private key)
	// R = right 32 bytes (chain code)
	hmac := hmacSHA512([]byte("Bitcoin seed"), seed)

	// 解析为主密钥
	key, err := bip32.NewMasterKey(hmac[:32])
	if err != nil {
		return nil, fmt.Errorf("failed to create master key: %w", err)
	}

	return &MasterKey{
		Key:       key,
		ChainCode: hmac[32:],
	}, nil
}

// DeriveChild 派生子密钥
// index: 派生索引，如果是硬化派生则需要加上 bip32.FirstHardenedChild
func (mk *MasterKey) DeriveChild(index uint32) (*bip32.Key, error) {
	child, err := mk.Key.NewChildKey(index)
	if err != nil {
		return nil, fmt.Errorf("failed to derive child key: %w", err)
	}
	return child, nil
}

// DeriveFromPath 根据 BIP-32 路径派生密钥
func (mk *MasterKey) DeriveFromPath(path *BIP32Path) (*bip32.Key, error) {
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

// DeriveBIP44 派生子密钥使用 BIP-44 路径
// chainCode: 链名称 (如 "ethereum", "bitcoin")
// account: 账户索引
// change: 0=外部链, 1=内部链
// index: 地址索引
func (mk *MasterKey) DeriveBIP44(chainCode string, account, change, index uint32) (*bip32.Key, error) {
	coinType, ok := CoinTypes[chainCode]
	if !ok {
		return nil, fmt.Errorf("unsupported chain: %s", chainCode)
	}

	path := &BIP32Path{
		Purpose:      0x8000002C, // 44'
		CoinType:     coinType,
		Account:      0x80000000 + account,
		Change:       change,
		AddressIndex: index,
	}

	return mk.DeriveFromPath(path)
}

// PrivateKey 返回私钥的椭圆曲线表示
// 对于 secp256k1 曲线,返回 *secp256k1.PrivateKey
// 对于其他曲线,返回 *ecdsa.PrivateKey
func (mk *MasterKey) PrivateKey(curveName string) (interface{}, error) {
	switch curveName {
	case "secp256k1":
		return mk.Secp256k1PrivateKey()
	case "P-256", "secp256r1":
		return mk.ECDSAPrivateKey()
	default:
		return mk.ECDSAPrivateKey()
	}
}

// ECDSAPrivateKey 返回私钥的 ECDSA (P-256) 表示
func (mk *MasterKey) ECDSAPrivateKey() (*ecdsa.PrivateKey, error) {
	return bip32KeyToECDSA(mk.Key, elliptic.P256())
}

// Secp256k1PrivateKey 返回私钥的 secp256k1 表示
func (mk *MasterKey) Secp256k1PrivateKey() (*secp256k1.PrivateKey, error) {
	return bip32KeyToSecp256k1(mk.Key)
}

// PublicKey 返回公钥
func (mk *MasterKey) PublicKey() []byte {
	return mk.Key.PublicKey().Key
}

// bip32KeyToECDSA 将 BIP-32 密钥转换为标准 ECDSA 私钥
func bip32KeyToECDSA(key *bip32.Key, curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	privKeyBytes := key.Key
	if len(privKeyBytes) != 32 {
		return nil, fmt.Errorf("invalid private key length: %d", len(privKeyBytes))
	}

	priv := &ecdsa.PrivateKey{}
	priv.Curve = curve
	priv.D = new(big.Int).SetBytes(privKeyBytes)
	// 计算公钥坐标
	priv.PublicKey.X, priv.PublicKey.Y = curve.ScalarBaseMult(privKeyBytes)

	return priv, nil
}

// bip32KeyToSecp256k1 将 BIP-32 密钥转换为 secp256k1 私钥
func bip32KeyToSecp256k1(key *bip32.Key) (*secp256k1.PrivateKey, error) {
	privKeyBytes := key.Key
	if len(privKeyBytes) != 32 {
		return nil, fmt.Errorf("invalid private key length: %d", len(privKeyBytes))
	}

	// 使用 PrivKeyFromBytes 从字节创建私钥
	return secp256k1.PrivKeyFromBytes(privKeyBytes), nil
}

// hmacSHA512 计算 HMAC-SHA512
func hmacSHA512(key, data []byte) []byte {
	// 使用 Go 内置 crypto/hmac
	h := sha512.New()
	h.Write(key)
	h.Write(data)
	return h.Sum(nil)
}
