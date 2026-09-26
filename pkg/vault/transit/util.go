package transit

import (
	"fmt"
	"strings"
)

const (
	CoreTransit       = "core"
	OperationsTransit = "operations"
	UserTransit       = "user"

	MasterKeySeedKeyName = "%s-seed"
	OperationsKeyName    = "%s-privkey"
	UserKeyName          = "%s-privkey"

	DataEncryptionKeyType = "aes256-gcm96"
)

// GetKeyNameForCore 获取负责对应区块链核心密钥的 key name
func GetKeyNameForCore(chainCode string) string {
	return fmt.Sprintf(MasterKeySeedKeyName, chainCode)
}

// GetKeyNameForOperations 获取负责对应区块链运营密钥的 key name
func GetKeyNameForOperations(chainCode string) string {
	return fmt.Sprintf(OperationsKeyName, chainCode)
}

// GetKeyNameForUser 获取负责对应区块链用户密钥的 key name
func GetKeyNameForUser(chainCode string) string {
	return fmt.Sprintf(UserKeyName, chainCode)
}

func Bip44PathToContext(bip44Path string) string {
	// 将 / 替换为 - ，然后再去掉字符 '
	result := strings.ReplaceAll(bip44Path, "/", "-")
	result = strings.ReplaceAll(result, "'", "")
	return result
}
