package keyutil

type AccountUsage uint32

const (
	KEY_USAGE_OPERATIONAL AccountUsage = 0 // 使用运营密钥进行签名；场景：归集、出账
	KEY_USAGE_USER        AccountUsage = 1 // 使用用户密钥进行签名出账；场景：归集

	KEY_USAGE_UNKNOWN AccountUsage = ^AccountUsage(0) // 未知，不可用
)

// 0 = KEY_USAGE_OPERATIONAL
// 1 = KEY_USAGE_USER
// else = KEY_USAGE_UNKNOWN
func ToAccountUsage(v uint32) AccountUsage {
	switch v {
	case 0:
		return KEY_USAGE_OPERATIONAL
	case 1:
		return KEY_USAGE_USER
	default:
		return KEY_USAGE_UNKNOWN
	}
}

func (u AccountUsage) ToUin32() uint32 {
	return uint32(u)
}
