package hdwallet

import (
	"crypto/rand"
	"fmt"

	"github.com/tyler-smith/go-bip32"
)

const (
	HardenedMark = 0x80000000 // 强化派生的标记数字

	BIP44Purpose = 0x8000002C // 44' hardened

	// BIP-44 路径 /Account/
	// 运营
	AccountOperations uint32 = 0

	// BIP-44 路径 /Account/
	// 用户
	AccountUser uint32 = 1

	// 根据 BIP-44 路径标准 change 表示找零地址，
	// 其中 0 表示外部地址（External）；1 内部地址（Internal / Change）
	//
	// 例如 通常在 web3 钱包需要收款时，可以生成很多个收款地址（外部）
	// 当在使用 UTXO 模型币（如BTC）需要找零时，可以生成内部地址
	//
	// 对于本系统来说，change 的值不那么重要
	// 所以该系统中，change 层级只使用 0
	ChangeExternal uint32 = 0
)

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

// GenerateBip32Key 生成一个新的 HD 主密钥
// 使用 cryptographically secure random 作为种子。
//
// 返回值：
//   - master: BIP-32 主密钥，可直接用于派生子密钥
//   - seed: 32 字节原始种子，调用方负责在 defer 中通过 securestore.Memzero 擦除
//   - err: 错误信息
//
// 安全要点：seed 包含主密钥的全部熵，必须在内存中显式擦除后方可释放。
func GenerateBip32Key() (master *bip32.Key, seed []byte, err error) {
	seed = make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, fmt.Errorf("failed to generate random seed: %w", err)
	}

	if len(seed) < 16 || len(seed) > 32 {
		return nil, nil, fmt.Errorf("seed length must be between 16 and 32 bytes")
	}
	master, err = bip32.NewMasterKey(seed)
	return master, seed, err
}

// OperationsPath 返回运营账号 Account 层级的 BIP-44 路径字符串
// m/44'/coin_type'/account'
func OperationsPath(chainCode string) (string, error) {
	coinType, err := CoinTypeFromChainCode(chainCode)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("m/44'/%d'/%d'", coinType, AccountOperations), nil
}

// UserPath 返回用户账号 Account 层级的 BIP-44 路径字符串
// m/44'/coin_type'/account'
func UserPath(chainCode string) (string, error) {
	coinType, err := CoinTypeFromChainCode(chainCode)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("m/44'/%d'/%d'", coinType, AccountUser), nil
}

// MasterKeyBIP44Path 返回主密钥的 BIP-44 路径字符串
// m/44'/coin_type'
func MasterKeyPath(chainCode string) (string, error) {
	coinType, err := CoinTypeFromChainCode(chainCode)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("m/44'/%d'", coinType), nil
}

// CoinTypeFromChainCode 根据链代码获取 coin_type
func CoinTypeFromChainCode(chainCode string) (uint32, error) {
	coinType, ok := CoinTypes[chainCode]
	if !ok {
		return 0, fmt.Errorf("%s chain does not support the bip-44 specification", chainCode)
	}
	// 移除强化派生前缀，返回实际的 coin_type
	return coinType - 0x80000000, nil
}

// {@link context} m/44'/coin_type'/account'
// {@link change} /change
// {@link accountIdx} /0,1,2....
func ChildPath(context string, change uint32, accountIdx uint32) string {
	return fmt.Sprintf("%s/%d/%d", context, change, accountIdx)
}
