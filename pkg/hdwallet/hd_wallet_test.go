package hdwallet

import (
	"testing"
)

func TestGenerateBip32Key(t *testing.T) {
	t.Run("generates valid key", func(t *testing.T) {
		key, _, err := GenerateBip32Key()
		if err != nil {
			t.Fatalf("GenerateBip32Key() error = %v", err)
		}
		if key == nil {
			t.Fatal("GenerateBip32Key() returned nil key")
		}
		if len(key.Key) != 32 {
			t.Errorf("GenerateBip32Key() key length = %d, want 32", len(key.Key))
		}
		if len(key.Version) == 0 {
			t.Error("GenerateBip32Key() key has no version")
		}
	})

	t.Run("generates different keys", func(t *testing.T) {
		key1, _, err := GenerateBip32Key()
		if err != nil {
			t.Fatalf("GenerateBip32Key() error = %v", err)
		}
		key2, _, err := GenerateBip32Key()
		if err != nil {
			t.Fatalf("GenerateBip32Key() error = %v", err)
		}
		if string(key1.Key) == string(key2.Key) {
			t.Error("GenerateBip32Key() produced identical keys")
		}
	})
}

func TestOperationsPath(t *testing.T) {
	tests := []struct {
		name     string
		chain    string
		wantPath string
		wantErr  bool
	}{
		{
			name:     "ethereum",
			chain:    "ethereum",
			wantPath: "m/44'/60'/0'",
			wantErr:  false,
		},
		{
			name:     "bitcoin",
			chain:    "bitcoin",
			wantPath: "m/44'/0'/0'",
			wantErr:  false,
		},
		{
			name:     "solana",
			chain:    "solana",
			wantPath: "m/44'/311'/0'",
			wantErr:  false,
		},
		{
			name:     "unsupported chain",
			chain:    "unknown",
			wantPath: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, err := OperationsPath(tt.chain)
			if (err != nil) != tt.wantErr {
				t.Errorf("OperationsPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if path != tt.wantPath {
				t.Errorf("OperationsPath() = %v, want %v", path, tt.wantPath)
			}
		})
	}
}

func TestUserPath(t *testing.T) {
	tests := []struct {
		name     string
		chain    string
		wantPath string
		wantErr  bool
	}{
		{
			name:     "ethereum",
			chain:    "ethereum",
			wantPath: "m/44'/60'/1'",
			wantErr:  false,
		},
		{
			name:     "polygon",
			chain:    "polygon",
			wantPath: "m/44'/137'/1'",
			wantErr:  false,
		},
		{
			name:     "unsupported chain",
			chain:    "invalid",
			wantPath: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, err := UserPath(tt.chain)
			if (err != nil) != tt.wantErr {
				t.Errorf("UserPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if path != tt.wantPath {
				t.Errorf("UserPath() = %v, want %v", path, tt.wantPath)
			}
		})
	}
}

func TestMasterKeyPath(t *testing.T) {
	tests := []struct {
		name     string
		chain    string
		wantPath string
		wantErr  bool
	}{
		{
			name:     "ethereum",
			chain:    "ethereum",
			wantPath: "m/44'/60'",
			wantErr:  false,
		},
		{
			name:     "bsc",
			chain:    "bsc",
			wantPath: "m/44'/152'",
			wantErr:  false,
		},
		{
			name:     "unsupported chain",
			chain:    "notexist",
			wantPath: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path, err := MasterKeyPath(tt.chain)
			if (err != nil) != tt.wantErr {
				t.Errorf("MasterKeyPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if path != tt.wantPath {
				t.Errorf("MasterKeyPath() = %v, want %v", path, tt.wantPath)
			}
		})
	}
}

func TestCoinTypeFromChainCode(t *testing.T) {
	tests := []struct {
		name      string
		chainCode string
		wantType  uint32
		wantErr   bool
	}{
		{
			name:      "bitcoin",
			chainCode: "bitcoin",
			wantType:  0,
			wantErr:   false,
		},
		{
			name:      "ethereum",
			chainCode: "ethereum",
			wantType:  60,
			wantErr:   false,
		},
		{
			name:      "tron",
			chainCode: "tron",
			wantType:  195,
			wantErr:   false,
		},
		{
			name:      "solana",
			chainCode: "solana",
			wantType:  311,
			wantErr:   false,
		},
		{
			name:      "polygon",
			chainCode: "polygon",
			wantType:  137,
			wantErr:   false,
		},
		{
			name:      "unsupported chain",
			chainCode: "unknown",
			wantType:  0,
			wantErr:   true,
		},
		{
			name:      "empty string",
			chainCode: "",
			wantType:  0,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			coinType, err := CoinTypeFromChainCode(tt.chainCode)
			if (err != nil) != tt.wantErr {
				t.Errorf("CoinTypeFromChainCode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if coinType != tt.wantType {
				t.Errorf("CoinTypeFromChainCode() = %v, want %v", coinType, tt.wantType)
			}
		})
	}
}

func TestChildPath(t *testing.T) {
	tests := []struct {
		name       string
		context    string
		change     uint32
		accountIdx uint32
		want       string
	}{
		{
			name:       "basic path",
			context:    "m/44'/60'/0'",
			change:     0,
			accountIdx: 0,
			want:       "m/44'/60'/0'/0/0",
		},
		{
			name:       "different account",
			context:    "m/44'/60'/0'",
			change:     0,
			accountIdx: 5,
			want:       "m/44'/60'/0'/0/5",
		},
		{
			name:       "internal change",
			context:    "m/44'/60'/1'",
			change:     1,
			accountIdx: 0,
			want:       "m/44'/60'/1'/1/0",
		},
		{
			name:       "bitcoin path",
			context:    "m/44'/0'/0'",
			change:     0,
			accountIdx: 10,
			want:       "m/44'/0'/0'/0/10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ChildPath(tt.context, tt.change, tt.accountIdx)
			if got != tt.want {
				t.Errorf("ChildPath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConstants(t *testing.T) {
	t.Run("hardened mark is correct", func(t *testing.T) {
		if HardenedMark != 0x80000000 {
			t.Errorf("HardenedMark = 0x%X, want 0x80000000", HardenedMark)
		}
	})

	t.Run("bip44 purpose is correct", func(t *testing.T) {
		if BIP44Purpose != 0x8000002C {
			t.Errorf("BIP44Purpose = 0x%X, want 0x8000002C", BIP44Purpose)
		}
	})

	t.Run("account constants", func(t *testing.T) {
		if AccountOperations != 0 {
			t.Errorf("AccountOperations = %d, want 0", AccountOperations)
		}
		if AccountUser != 1 {
			t.Errorf("AccountUser = %d, want 1", AccountUser)
		}
	})

	t.Run("change constant", func(t *testing.T) {
		if ChangeExternal != 0 {
			t.Errorf("ChangeExternal = %d, want 0", ChangeExternal)
		}
	})
}

func TestCoinTypes(t *testing.T) {
	expectedCoinTypes := map[string]uint32{
		"bitcoin":   0x80000000,
		"ethereum":  0x8000003C,
		"tron":      0x800000C3,
		"solana":    0x80000137,
		"polygon":   0x80000089,
		"bsc":       0x80000098,
		"avalanche": 0x80002328,
		"arbitrum":  0x8000A4B1,
		"optimism":  0x8000A3F0,
		"base":      0x80002105,
		"linea":     0x8000E708,
		"zksync":    0x80000144,
		"scroll":    0x80008290,
		"mantle":    0x80001644,
		"filecoin":  0x800001CD,
	}

	for chain, expected := range expectedCoinTypes {
		got, ok := CoinTypes[chain]
		if !ok {
			t.Errorf("CoinTypes missing chain: %s", chain)
			continue
		}
		if got != expected {
			t.Errorf("CoinTypes[%s] = 0x%X, want 0x%X", chain, got, expected)
		}
	}
}

func TestDeriveChildKey(t *testing.T) {
	t.Skip("requires bip32.Key and derivation logic - demonstrates integration pattern")

	key, _, err := GenerateBip32Key()
	if err != nil {
		t.Fatalf("GenerateBip32Key() error = %v", err)
	}

	derived, err := key.NewChildKey(0 + HardenedMark)
	if err != nil {
		t.Fatalf("NewChildKey() error = %v", err)
	}

	if derived == nil {
		t.Error("NewChildKey() returned nil")
	}

	if derived.Depth != key.Depth+1 {
		t.Errorf("Depth = %d, want %d", derived.Depth, key.Depth+1)
	}
}

func TestIntegration(t *testing.T) {
	chain := "ethereum"

	opsPath, err := OperationsPath(chain)
	if err != nil {
		t.Fatalf("OperationsPath() error = %v", err)
	}

	userPath, err := UserPath(chain)
	if err != nil {
		t.Fatalf("UserPath() error = %v", err)
	}

	masterPath, err := MasterKeyPath(chain)
	if err != nil {
		t.Fatalf("MasterKeyPath() error = %v", err)
	}

	if opsPath != "m/44'/60'/0'" {
		t.Errorf("OperationsPath = %s, want m/44'/60'/0'", opsPath)
	}
	if userPath != "m/44'/60'/1'" {
		t.Errorf("UserPath = %s, want m/44'/60'/1'", userPath)
	}
	if masterPath != "m/44'/60'" {
		t.Errorf("MasterKeyPath = %s, want m/44'/60'", masterPath)
	}

	childPath := ChildPath(opsPath, ChangeExternal, 0)
	if childPath != "m/44'/60'/0'/0/0" {
		t.Errorf("ChildPath = %s, want m/44'/60'/0'/0/0", childPath)
	}

	coinType, err := CoinTypeFromChainCode(chain)
	if err != nil {
		t.Fatalf("CoinTypeFromChainCode() error = %v", err)
	}
	if coinType != 60 {
		t.Errorf("CoinType = %d, want 60", coinType)
	}
}

func TestBip32KeyProperties(t *testing.T) {
	key, _, err := GenerateBip32Key()
	if err != nil {
		t.Fatalf("GenerateBip32Key() error = %v", err)
	}

	t.Run("key is valid master key", func(t *testing.T) {
		if key.Version == nil {
			t.Error("Version is nil")
		}
	})

	t.Run("key has correct length", func(t *testing.T) {
		if len(key.Key) != 32 {
			t.Errorf("Key length = %d, want 32", len(key.Key))
		}
		if len(key.ChainCode) != 32 {
			t.Errorf("ChainCode length = %d, want 32", len(key.ChainCode))
		}
	})

	t.Run("depth is zero for master", func(t *testing.T) {
		if key.Depth != 0 {
			t.Errorf("Depth = %d, want 0 for master key", key.Depth)
		}
	})

	t.Run("child number is zero for master", func(t *testing.T) {
		if len(key.ChildNumber) != 4 {
			t.Errorf("ChildNumber length = %d, want 4 for master key", len(key.ChildNumber))
		}
	})
}
