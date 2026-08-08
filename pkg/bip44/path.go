// Package bip44 定义了 BIP-44 标准路径和相关工具
// 用于协调 Coordinator 和 Signer 服务之间的密钥派生
package bip44

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// KeyUsage 定义密钥用途
type KeyUsage int

const (
	// Operational 运营密钥 - m/44'/coin'/0'/1/x
	Operational KeyUsage = iota
	// User 用户密钥 - m/44'/coin'/1'/1/x
	User
	// Backup 备份密钥 - m/44'/coin'/2'/0/x
	Backup
)

// String 返回 KeyUsage 的字符串表示
func (u KeyUsage) String() string {
	switch u {
	case Operational:
		return "operational"
	case User:
		return "user"
	case Backup:
		return "backup"
	default:
		return "unknown"
	}
}

// BIP44Path 表示完整的 BIP-44 派生路径
type BIP44Path struct {
	Purpose      uint32   // BIP purpose, 固定为 44
	CoinType     uint32   // 链 coin_type (硬化)
	Account      uint32   // 账户索引 (硬化)
	Change       uint32   // 0=外部链(收款), 1=内部链(找零/运营)
	AddressIndex uint32   // 地址索引
	Usage        KeyUsage // 密钥用途
}

// String 返回路径的字符串表示，如 "m/44'/60'/0'/1/0"
func (p *BIP44Path) String() string {
	return fmt.Sprintf("m/%d'/%d'/%d'/%d/%d",
		p.Purpose-0x80000000,
		p.CoinType-0x80000000,
		p.Account-0x80000000,
		p.Change,
		p.AddressIndex)
}

// FullPath 返回包含用途信息的完整路径描述
func (p *BIP44Path) FullPath() string {
	return fmt.Sprintf("%s (%s)", p.String(), p.Usage.String())
}

// ToContext 生成 Vault Transit Engine 所需的派生 context
// 使用 SHA256(path) 作为 context，确保相同路径只能解密对应密钥
func (p *BIP44Path) ToContext() string {
	pathStr := p.String()
	hash := sha256.Sum256([]byte(pathStr))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// ToHardenedPath 将 BIP44Path 转换为 go-bip32 的硬化派生索引
func (p *BIP44Path) ToHardenedPath() []uint32 {
	return []uint32{p.Purpose, p.CoinType, p.Account, p.Change, p.AddressIndex}
}

// CoinTypes 定义了各区块链的 BIP-44 coin_type
// 参考: https://github.com/satoshilabs/slips/blob/master/slip-0044.md
var CoinTypes = map[string]uint32{
	"bitcoin":   0x80000000, // 0'
	"ethereum":  0x8000003C, // 60'
	"tron":      0x800000C3, // 195'
	"solana":    0x80000137, // 311'
	"polygon":   0x80000089, // 137'
	"bsc":       0x80000098, // 152'
	"avalanche": 0x80002328, // 9000'
	"arbitrum":  0x8000A4B1, // 42161'
	"optimism":  0x8000A3F0, // 42000'
	"base":      0x80002105, // 8453'
	"linea":     0x8000E708, // 59144'
	"zksync":    0x80000144, // 324'
	"scroll":    0x80008290, // 534352'
	"mantle":    0x80001644, // 5700'
	"filecoin":  0x800001CD, // 461'
}

// CoinTypeFromChainCode 根据链代码获取 coin_type
func CoinTypeFromChainCode(chainCode string) (uint32, error) {
	coinType, ok := CoinTypes[chainCode]
	if !ok {
		return 0, fmt.Errorf("unsupported chain: %s", chainCode)
	}
	// 移除硬化前缀，返回实际的 coin_type
	return coinType - 0x80000000, nil
}

// NewOperationalPath 创建运营密钥路径
// m/44'/coin_type'/0'/1/address_index
func NewOperationalPath(coinType uint32, addressIndex uint32) *BIP44Path {
	return &BIP44Path{
		Purpose:      0x8000002C, // 44'
		CoinType:     0x80000000 + coinType,
		Account:      0x80000000, // 0'
		Change:       1,          // 内部链 (运营用途)
		AddressIndex: addressIndex,
		Usage:        Operational,
	}
}

// NewUserPath 创建用户密钥路径
// m/44'/coin_type'/1'/1/address_index
func NewUserPath(coinType uint32, addressIndex uint32) *BIP44Path {
	return &BIP44Path{
		Purpose:      0x8000002C, // 44'
		CoinType:     0x80000000 + coinType,
		Account:      0x80000001, // 1'
		Change:       1,          // 内部链 (用户密钥)
		AddressIndex: addressIndex,
		Usage:        User,
	}
}

// NewBackupPath 创建备份密钥路径
// m/44'/coin_type'/2'/0/0
func NewBackupPath(coinType uint32) *BIP44Path {
	return &BIP44Path{
		Purpose:      0x8000002C, // 44'
		CoinType:     0x80000000 + coinType,
		Account:      0x80000002, // 2'
		Change:       0,          // 外部链
		AddressIndex: 0,
		Usage:        Backup,
	}
}

// FromUsage 根据用途创建默认路径
func FromUsage(coinType uint32, usage KeyUsage, addressIndex uint32) *BIP44Path {
	switch usage {
	case Operational:
		return NewOperationalPath(coinType, addressIndex)
	case User:
		return NewUserPath(coinType, addressIndex)
	case Backup:
		return NewBackupPath(coinType)
	default:
		return NewOperationalPath(coinType, addressIndex)
	}
}

// MasterKeyPath 返回主密钥的 BIP-44 路径
// m/44'/coin_type'/0'/0/0
func MasterKeyPath(chainCode string) (*BIP44Path, error) {
	coinType, err := CoinTypeFromChainCode(chainCode)
	if err != nil {
		return nil, err
	}
	return &BIP44Path{
		Purpose:      0x8000002C, // 44'
		CoinType:     0x80000000 + coinType,
		Account:      0x80000000, // 0'
		Change:       0,
		AddressIndex: 0,
		Usage:        Operational, // 主密钥用途标记为运营
	}, nil
}

// MasterKeyBIP44Path 返回主密钥的 BIP-44 路径字符串
// m/44'/coin_type'/0'/0/0
func MasterKeyBIP44Path(chainCode string) (string, error) {
	coinType, err := CoinTypeFromChainCode(chainCode)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("m/44'/%d'/0'/0/0", coinType), nil
}

// GenerateDerivedKeyName 生成派生密钥名称
// 格式: {chain}-child-{usage}-{index}
func GenerateDerivedKeyName(chainCode string, usage KeyUsage, addressIndex uint32) string {
	switch usage {
	case Operational:
		return fmt.Sprintf("%s-child-op-%d", chainCode, addressIndex)
	case User:
		return fmt.Sprintf("%s-child-user-%d", chainCode, addressIndex)
	default:
		return fmt.Sprintf("%s-child-op-%d", chainCode, addressIndex)
	}
}
