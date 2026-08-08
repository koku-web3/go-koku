package hd

import (
	"testing"
)

// TestGenerateMasterKey 测试生成主密钥
func TestGenerateMasterKey(t *testing.T) {
	masterKey, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	if masterKey == nil {
		t.Fatal("Master key is nil")
	}

	if len(masterKey.ChainCode) != 32 {
		t.Errorf("Chain code length should be 32, got %d", len(masterKey.ChainCode))
	}
}

// TestNewMasterKeyFromSeed 测试从种子创建主密钥
func TestNewMasterKeyFromSeed(t *testing.T) {
	// 使用 64 字节种子
	seed := make([]byte, 64)
	for i := range seed {
		seed[i] = byte(i)
	}

	masterKey, err := NewMasterKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("Failed to create master key from seed: %v", err)
	}

	if masterKey == nil {
		t.Fatal("Master key is nil")
	}

	// 验证私钥长度
	if len(masterKey.Key.Key) != 32 {
		t.Errorf("Private key length should be 32, got %d", len(masterKey.Key.Key))
	}
}

// TestNewMasterKeyFromSeedInvalidLength 测试无效种子长度
func TestNewMasterKeyFromSeedInvalidLength(t *testing.T) {
	tests := []struct {
		name  string
		seed  []byte
		valid bool
	}{
		{"too short", []byte{1, 2, 3}, false},
		{"minimum valid", make([]byte, 16), true},
		{"maximum valid", make([]byte, 64), true},
		{"too long", make([]byte, 65), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewMasterKeyFromSeed(tt.seed)
			if tt.valid && err != nil {
				t.Errorf("Expected valid seed, got error: %v", err)
			}
			if !tt.valid && err == nil {
				t.Error("Expected error for invalid seed, got nil")
			}
		})
	}
}

// TestDeriveChild 测试派生子密钥
func TestDeriveChild(t *testing.T) {
	masterKey, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	// 派生第一个硬化子密钥
	childKey, err := masterKey.DeriveChild(0x80000000) // 0'
	if err != nil {
		t.Fatalf("Failed to derive child key: %v", err)
	}

	// 子密钥应该与主密钥不同
	if childKey.B58Serialize() == masterKey.Key.B58Serialize() {
		t.Error("Child key should be different from master key")
	}

	// 子密钥应该仍然是有效的 32 字节私钥
	if len(childKey.Key) != 32 {
		t.Errorf("Child key length should be 32, got %d", len(childKey.Key))
	}
}

// TestDeriveBIP44 测试 BIP-44 派生
func TestDeriveBIP44(t *testing.T) {
	masterKey, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	tests := []struct {
		chainCode string
		account   uint32
		change    uint32
		index     uint32
		wantErr   bool
	}{
		{"ethereum", 0, 0, 0, false},
		{"bitcoin", 0, 0, 0, false},
		{"tron", 0, 0, 0, false},
		{"unknown", 0, 0, 0, true}, // 不支持的链
	}

	for _, tt := range tests {
		t.Run(tt.chainCode, func(t *testing.T) {
			key, err := masterKey.DeriveBIP44(tt.chainCode, tt.account, tt.change, tt.index)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error for unsupported chain")
				}
				return
			}

			if err != nil {
				t.Errorf("Failed to derive BIP44 key: %v", err)
				return
			}

			// 验证派生出的密钥
			if len(key.Key) != 32 {
				t.Errorf("Key length should be 32, got %d", len(key.Key))
			}
		})
	}
}

// TestDeriveFromPath 测试从路径派生
func TestDeriveFromPath(t *testing.T) {
	masterKey, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	path, err := DefaultBIP44Path("ethereum")
	if err != nil {
		t.Fatalf("Failed to get default BIP44 path: %v", err)
	}

	key, err := masterKey.DeriveFromPath(path)
	if err != nil {
		t.Fatalf("Failed to derive from path: %v", err)
	}

	if len(key.Key) != 32 {
		t.Errorf("Key length should be 32, got %d", len(key.Key))
	}
}

// TestCoinTypes 测试 coin type 映射
func TestCoinTypes(t *testing.T) {
	expected := map[string]uint32{
		"bitcoin":  0x80000000,
		"ethereum": 0x8000003C,
		"tron":     0x800000C3,
		"solana":   0x80000137,
		"polygon":  0x80000089,
	}

	for chain, expectedType := range expected {
		actualType, ok := CoinTypes[chain]
		if !ok {
			t.Errorf("Chain %s not found in CoinTypes", chain)
			continue
		}
		if actualType != expectedType {
			t.Errorf("CoinType for %s: expected %x, got %x", chain, expectedType, actualType)
		}
	}
}

// TestBIP32PathString 测试路径字符串表示
func TestBIP32PathString(t *testing.T) {
	path := &BIP32Path{
		Purpose:      0x8000002C,
		CoinType:     0x8000003C,
		Account:      0x80000000,
		Change:       0,
		AddressIndex: 0,
	}

	expected := "m/44'/60'/0'/0/0"
	if path.String() != expected {
		t.Errorf("Expected %s, got %s", expected, path.String())
	}
}

// TestDefaultBIP44Path 测试默认 BIP-44 路径
func TestDefaultBIP44Path(t *testing.T) {
	tests := []struct {
		chainCode string
		wantErr   bool
	}{
		{"ethereum", false},
		{"bitcoin", false},
		{"tron", false},
		{"unknown", true},
	}

	for _, tt := range tests {
		t.Run(tt.chainCode, func(t *testing.T) {
			path, err := DefaultBIP44Path(tt.chainCode)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error for unsupported chain")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			// 验证路径结构
			if path.Purpose != 0x8000002C {
				t.Errorf("Purpose should be 44', got %d", path.Purpose-0x80000000)
			}
			if path.Account != 0x80000000 {
				t.Errorf("Account should be 0', got %d", path.Account-0x80000000)
			}
			if path.Change != 0 {
				t.Errorf("Change should be 0, got %d", path.Change)
			}
			if path.AddressIndex != 0 {
				t.Errorf("AddressIndex should be 0, got %d", path.AddressIndex)
			}
		})
	}
}

// TestMasterKeyDeterministic 测试相同种子生成相同主密钥
func TestMasterKeyDeterministic(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	masterKey1, err := NewMasterKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("Failed to create master key 1: %v", err)
	}

	masterKey2, err := NewMasterKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("Failed to create master key 2: %v", err)
	}

	// 相同种子应生成相同主密钥
	if masterKey1.Key.B58Serialize() != masterKey2.Key.B58Serialize() {
		t.Error("Same seed should produce same master key")
	}
}

// TestECDSAPrivateKey 测试 ECDSA 私钥转换
func TestECDSAPrivateKey(t *testing.T) {
	masterKey, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	ecdsaKey, err := masterKey.ECDSAPrivateKey()
	if err != nil {
		t.Fatalf("Failed to convert to ECDSA private key: %v", err)
	}

	if ecdsaKey.Curve == nil {
		t.Error("ECDSA key curve should not be nil")
	}

	if ecdsaKey.D == nil {
		t.Error("ECDSA key D should not be nil")
	}
}

// TestSecp256k1PrivateKey 测试 secp256k1 私钥转换
func TestSecp256k1PrivateKey(t *testing.T) {
	masterKey, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("Failed to generate master key: %v", err)
	}

	secpKey, err := masterKey.Secp256k1PrivateKey()
	if err != nil {
		t.Fatalf("Failed to convert to secp256k1 private key: %v", err)
	}

	if secpKey == nil {
		t.Error("secp256k1 key should not be nil")
	}
}
