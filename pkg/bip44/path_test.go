package bip44

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestKeyUsage_String(t *testing.T) {
	tests := []struct {
		name     string
		usage    KeyUsage
		expected string
	}{
		{"Operational", Operational, "operational"},
		{"User", User, "user"},
		{"Backup", Backup, "backup"},
		{"Unknown", KeyUsage(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.usage.String(); got != tt.expected {
				t.Errorf("KeyUsage.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestBIP44Path_String(t *testing.T) {
	tests := []struct {
		name     string
		path     *BIP44Path
		expected string
	}{
		{
			name: "standard path",
			path: &BIP44Path{
				Purpose:      0x8000002C,
				CoinType:     0x80000000,
				Account:      0x80000000,
				Change:       0,
				AddressIndex: 0,
			},
			expected: "m/44'/0'/0'/0/0",
		},
		{
			name: "ethereum path",
			path: &BIP44Path{
				Purpose:      0x8000002C,
				CoinType:     0x8000003C,
				Account:      0x80000000,
				Change:       1,
				AddressIndex: 5,
			},
			expected: "m/44'/60'/0'/1/5",
		},
		{
			name: "bitcoin user path",
			path: &BIP44Path{
				Purpose:      0x8000002C,
				CoinType:     0x80000000,
				Account:      0x80000001,
				Change:       1,
				AddressIndex: 10,
			},
			expected: "m/44'/0'/1'/1/10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.path.String(); got != tt.expected {
				t.Errorf("BIP44Path.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestBIP44Path_FullPath(t *testing.T) {
	path := &BIP44Path{
		Purpose:      0x8000002C,
		CoinType:     0x8000003C,
		Account:      0x80000000,
		Change:       1,
		AddressIndex: 0,
		Usage:        Operational,
	}

	expected := "m/44'/60'/0'/1/0 (operational)"
	if got := path.FullPath(); got != expected {
		t.Errorf("BIP44Path.FullPath() = %v, want %v", got, expected)
	}
}

func TestBIP44Path_ToContext(t *testing.T) {
	path := &BIP44Path{
		Purpose:      0x8000002C,
		CoinType:     0x8000003C,
		Account:      0x80000000,
		Change:       1,
		AddressIndex: 0,
	}

	// 计算期望的 context: SHA256("m/44'/60'/0'/1/0")
	pathStr := "m/44'/60'/0'/1/0"
	hash := sha256.Sum256([]byte(pathStr))
	expected := base64.StdEncoding.EncodeToString(hash[:])

	if got := path.ToContext(); got != expected {
		t.Errorf("BIP44Path.ToContext() = %v, want %v", got, expected)
	}

	// 验证相同路径生成相同的 context
	if got2 := path.ToContext(); got2 != expected {
		t.Errorf("BIP44Path.ToContext() 不稳定: got %v, want %v", got2, expected)
	}
}

func TestBIP44Path_ToContext_Deterministic(t *testing.T) {
	// 验证不同路径生成不同的 context
	path1 := NewOperationalPath(60, 0)
	path2 := NewOperationalPath(60, 1)

	context1 := path1.ToContext()
	context2 := path2.ToContext()

	if context1 == context2 {
		t.Error("不同路径应生成不同的 context")
	}
}

func TestBIP44Path_ToHardenedPath(t *testing.T) {
	path := &BIP44Path{
		Purpose:      0x8000002C,
		CoinType:     0x8000003C,
		Account:      0x80000000,
		Change:       1,
		AddressIndex: 5,
	}

	expected := []uint32{0x8000002C, 0x8000003C, 0x80000000, 1, 5}
	got := path.ToHardenedPath()

	if len(got) != len(expected) {
		t.Errorf("ToHardenedPath() 长度 = %d, want %d", len(got), len(expected))
		return
	}

	for i := range expected {
		if got[i] != expected[i] {
			t.Errorf("ToHardenedPath()[%d] = %d, want %d", i, got[i], expected[i])
		}
	}
}

func TestCoinTypes(t *testing.T) {
	tests := []struct {
		chain            string
		hardenedValue    uint32
		expectedCoinType uint32
	}{
		{"bitcoin", 0x80000000, 0},
		{"ethereum", 0x8000003C, 60},
		{"tron", 0x800000C3, 195},
		{"solana", 0x80000137, 311},
		{"polygon", 0x80000089, 137},
		{"bsc", 0x80000098, 152},
		{"avalanche", 0x80002328, 9000},
		{"arbitrum", 0x8000A4B1, 42161},
		{"optimism", 0x8000A3F0, 41968},
		{"base", 0x80002105, 8453},
		{"linea", 0x8000E708, 59144},
		{"zksync", 0x80000144, 324},
		{"scroll", 0x80008290, 33424},
		{"mantle", 0x80001644, 5700},
		{"filecoin", 0x800001CD, 461},
	}

	for _, tt := range tests {
		t.Run(tt.chain, func(t *testing.T) {
			coinTypeHardened, ok := CoinTypes[tt.chain]
			if !ok {
				t.Errorf("Chain %s not found in CoinTypes", tt.chain)
				return
			}
			if coinTypeHardened != tt.hardenedValue {
				t.Errorf("CoinTypes[%s] = 0x%08X, want 0x%08X", tt.chain, coinTypeHardened, tt.hardenedValue)
			}
			// 验证移除硬化前缀后等于 coin_type
			if coinTypeHardened-0x80000000 != tt.expectedCoinType {
				t.Errorf("CoinTypes[%s] - 0x80000000 = %d, want %d", tt.chain, coinTypeHardened-0x80000000, tt.expectedCoinType)
			}
		})
	}
}

func TestCoinTypeFromChainCode(t *testing.T) {
	tests := []struct {
		chain       string
		expected    uint32
		expectError bool
	}{
		{"ethereum", 60, false},
		{"bitcoin", 0, false},
		{"solana", 311, false},
		{"unsupported", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.chain, func(t *testing.T) {
			got, err := CoinTypeFromChainCode(tt.chain)
			if tt.expectError {
				if err == nil {
					t.Error("CoinTypeFromChainCode() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("CoinTypeFromChainCode() unexpected error: %v", err)
				return
			}
			if got != tt.expected {
				t.Errorf("CoinTypeFromChainCode() = %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestNewOperationalPath(t *testing.T) {
	path := NewOperationalPath(60, 5)

	if path.Purpose != 0x8000002C {
		t.Errorf("Purpose = %d, want %d", path.Purpose, 0x8000002C)
	}
	if path.CoinType != 0x8000003C {
		t.Errorf("CoinType = %d, want %d", path.CoinType, 0x8000003C)
	}
	if path.Account != 0x80000000 {
		t.Errorf("Account = %d, want %d", path.Account, 0x80000000)
	}
	if path.Change != 1 {
		t.Errorf("Change = %d, want %d", path.Change, 1)
	}
	if path.AddressIndex != 5 {
		t.Errorf("AddressIndex = %d, want %d", path.AddressIndex, 5)
	}
	if path.Usage != Operational {
		t.Errorf("Usage = %v, want Operational", path.Usage)
	}

	// 验证路径字符串
	expectedStr := "m/44'/60'/0'/1/5"
	if got := path.String(); got != expectedStr {
		t.Errorf("String() = %s, want %s", got, expectedStr)
	}
}

func TestNewUserPath(t *testing.T) {
	path := NewUserPath(60, 10)

	if path.Purpose != 0x8000002C {
		t.Errorf("Purpose = %d, want %d", path.Purpose, 0x8000002C)
	}
	if path.CoinType != 0x8000003C {
		t.Errorf("CoinType = %d, want %d", path.CoinType, 0x8000003C)
	}
	if path.Account != 0x80000001 {
		t.Errorf("Account = %d, want %d", path.Account, 0x80000001)
	}
	if path.Change != 1 {
		t.Errorf("Change = %d, want %d", path.Change, 1)
	}
	if path.AddressIndex != 10 {
		t.Errorf("AddressIndex = %d, want %d", path.AddressIndex, 10)
	}
	if path.Usage != User {
		t.Errorf("Usage = %v, want User", path.Usage)
	}

	// 验证路径字符串
	expectedStr := "m/44'/60'/1'/1/10"
	if got := path.String(); got != expectedStr {
		t.Errorf("String() = %s, want %s", got, expectedStr)
	}
}

func TestNewBackupPath(t *testing.T) {
	path := NewBackupPath(60)

	if path.Purpose != 0x8000002C {
		t.Errorf("Purpose = %d, want %d", path.Purpose, 0x8000002C)
	}
	if path.CoinType != 0x8000003C {
		t.Errorf("CoinType = %d, want %d", path.CoinType, 0x8000003C)
	}
	if path.Account != 0x80000002 {
		t.Errorf("Account = %d, want %d", path.Account, 0x80000002)
	}
	if path.Change != 0 {
		t.Errorf("Change = %d, want %d", path.Change, 0)
	}
	if path.AddressIndex != 0 {
		t.Errorf("AddressIndex = %d, want %d", path.AddressIndex, 0)
	}
	if path.Usage != Backup {
		t.Errorf("Usage = %v, want Backup", path.Usage)
	}

	// 验证路径字符串
	expectedStr := "m/44'/60'/2'/0/0"
	if got := path.String(); got != expectedStr {
		t.Errorf("String() = %s, want %s", got, expectedStr)
	}
}

func TestFromUsage(t *testing.T) {
	tests := []struct {
		name         string
		usage        KeyUsage
		coinType     uint32
		addressIndex uint32
		checkFunc    func(*BIP44Path)
	}{
		{
			name:         "Operational",
			usage:        Operational,
			coinType:     60,
			addressIndex: 5,
			checkFunc: func(p *BIP44Path) {
				if p.Account != 0x80000000 {
					t.Errorf("Account = %d, want %d", p.Account, 0x80000000)
				}
				if p.Change != 1 {
					t.Errorf("Change = %d, want %d", p.Change, 1)
				}
			},
		},
		{
			name:         "User",
			usage:        User,
			coinType:     60,
			addressIndex: 10,
			checkFunc: func(p *BIP44Path) {
				if p.Account != 0x80000001 {
					t.Errorf("Account = %d, want %d", p.Account, 0x80000001)
				}
				if p.Change != 1 {
					t.Errorf("Change = %d, want %d", p.Change, 1)
				}
			},
		},
		{
			name:         "Backup",
			usage:        Backup,
			coinType:     60,
			addressIndex: 0,
			checkFunc: func(p *BIP44Path) {
				if p.Account != 0x80000002 {
					t.Errorf("Account = %d, want %d", p.Account, 0x80000002)
				}
				if p.Change != 0 {
					t.Errorf("Change = %d, want %d", p.Change, 0)
				}
			},
		},
		{
			name:         "Unknown defaults to Operational",
			usage:        KeyUsage(99),
			coinType:     60,
			addressIndex: 3,
			checkFunc: func(p *BIP44Path) {
				if p.Usage != Operational {
					t.Errorf("Usage = %v, want Operational (default)", p.Usage)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := FromUsage(tt.coinType, tt.usage, tt.addressIndex)
			if path.CoinType != 0x80000000+tt.coinType {
				t.Errorf("CoinType = %d, want %d", path.CoinType, 0x80000000+tt.coinType)
			}
			if path.AddressIndex != tt.addressIndex {
				t.Errorf("AddressIndex = %d, want %d", path.AddressIndex, tt.addressIndex)
			}
			tt.checkFunc(path)
		})
	}
}

func TestMasterKeyPath(t *testing.T) {
	tests := []struct {
		chain       string
		expectError bool
		expectedStr string
	}{
		{"ethereum", false, "m/44'/60'/0'/0/0"},
		{"bitcoin", false, "m/44'/0'/0'/0/0"},
		{"solana", false, "m/44'/311'/0'/0/0"},
		{"unsupported", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.chain, func(t *testing.T) {
			path, err := MasterKeyPath(tt.chain)

			if tt.expectError {
				if err == nil {
					t.Error("MasterKeyPath() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("MasterKeyPath() unexpected error: %v", err)
				return
			}

			if path.Account != 0x80000000 {
				t.Errorf("Account = %d, want %d", path.Account, 0x80000000)
			}
			if path.Change != 0 {
				t.Errorf("Change = %d, want %d", path.Change, 0)
			}
			if path.AddressIndex != 0 {
				t.Errorf("AddressIndex = %d, want %d", path.AddressIndex, 0)
			}
			if path.Usage != Operational {
				t.Errorf("Usage = %v, want Operational", path.Usage)
			}

			if got := path.String(); got != tt.expectedStr {
				t.Errorf("String() = %s, want %s", got, tt.expectedStr)
			}
		})
	}
}

func TestMasterKeyBIP44Path(t *testing.T) {
	tests := []struct {
		chain       string
		expectError bool
		expected    string
	}{
		{"ethereum", false, "m/44'/60'/0'/0/0"},
		{"bitcoin", false, "m/44'/0'/0'/0/0"},
		{"unsupported", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.chain, func(t *testing.T) {
			got, err := MasterKeyBIP44Path(tt.chain)

			if tt.expectError {
				if err == nil {
					t.Error("MasterKeyBIP44Path() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("MasterKeyBIP44Path() unexpected error: %v", err)
				return
			}

			if got != tt.expected {
				t.Errorf("MasterKeyBIP44Path() = %s, want %s", got, tt.expected)
			}
		})
	}
}

func TestGenerateDerivedKeyName(t *testing.T) {
	tests := []struct {
		chain        string
		usage        KeyUsage
		addressIndex uint32
		expected     string
	}{
		{"ethereum", Operational, 0, "ethereum-child-op-0"},
		{"ethereum", Operational, 5, "ethereum-child-op-5"},
		{"ethereum", User, 10, "ethereum-child-user-10"},
		{"bitcoin", Backup, 0, "bitcoin-child-op-0"},     // Backup defaults to op
		{"solana", KeyUsage(99), 3, "solana-child-op-3"}, // Unknown defaults to op
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := GenerateDerivedKeyName(tt.chain, tt.usage, tt.addressIndex)
			if got != tt.expected {
				t.Errorf("GenerateDerivedKeyName() = %s, want %s", got, tt.expected)
			}
		})
	}
}

// Benchmark 测试
func BenchmarkBIP44Path_ToContext(b *testing.B) {
	path := NewOperationalPath(60, 5)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = path.ToContext()
	}
}

func BenchmarkBIP44Path_String(b *testing.B) {
	path := &BIP44Path{
		Purpose:      0x8000002C,
		CoinType:     0x8000003C,
		Account:      0x80000000,
		Change:       1,
		AddressIndex: 5,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = path.String()
	}
}

func BenchmarkCoinTypeFromChainCode(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CoinTypeFromChainCode("ethereum")
	}
}
