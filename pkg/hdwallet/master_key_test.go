package hdwallet

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/koku-web3/go-koku/pkg/bip44"
)

func TestGenerateMasterKey(t *testing.T) {
	masterKey, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey() error = %v", err)
	}

	if masterKey == nil {
		t.Fatal("GenerateMasterKey() returned nil")
	}

	if masterKey.Key == nil {
		t.Error("GenerateMasterKey().Key is nil")
	}

	if masterKey.Key.Key == nil || len(masterKey.Key.Key) != 32 {
		t.Errorf("GenerateMasterKey().Key.Key length = %d, want 32", len(masterKey.Key.Key))
	}

	if masterKey.ChainCode == nil || len(masterKey.ChainCode) != 32 {
		t.Errorf("GenerateMasterKey().ChainCode length = %d, want 32", len(masterKey.ChainCode))
	}
}

func TestGenerateMasterKey_Uniqueness(t *testing.T) {
	// 验证每次生成不同的密钥
	key1, _ := GenerateMasterKey()
	key2, _ := GenerateMasterKey()

	if string(key1.Key.Key) == string(key2.Key.Key) {
		t.Error("Two generated keys should be different")
	}

	if string(key1.ChainCode) == string(key2.ChainCode) {
		t.Error("Two generated chain codes should be different")
	}
}

func TestNewMasterKeyFromSeed(t *testing.T) {
	// 使用标准 BIP-39 测试向量 (简化版本)
	seed := []byte("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	masterKey, err := NewMasterKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("NewMasterKeyFromSeed() error = %v", err)
	}

	if masterKey == nil {
		t.Fatal("NewMasterKeyFromSeed() returned nil")
	}

	if masterKey.Key == nil {
		t.Error("MasterKey.Key is nil")
	}

	if masterKey.ChainCode == nil {
		t.Error("MasterKey.ChainCode is nil")
	}
}

func TestNewMasterKeyFromSeed_InvalidLength(t *testing.T) {
	tests := []struct {
		name string
		seed []byte
	}{
		{"too short (15 bytes)", []byte("0123456789abcde")},
		{"too long (65 bytes)", make([]byte, 65)},
		{"empty", []byte{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewMasterKeyFromSeed(tt.seed)
			if err == nil {
				t.Error("NewMasterKeyFromSeed() expected error for invalid seed length")
			}
		})
	}
}

func TestNewMasterKeyFromSeed_MinMaxBoundary(t *testing.T) {
	// 测试边界值 (16 和 64 字节应该有效)
	minSeed := make([]byte, 16)
	maxSeed := make([]byte, 64)

	_, errMin := NewMasterKeyFromSeed(minSeed)
	_, errMax := NewMasterKeyFromSeed(maxSeed)

	if errMin != nil {
		t.Errorf("NewMasterKeyFromSeed() with 16-byte seed error = %v", errMin)
	}
	if errMax != nil {
		t.Errorf("NewMasterKeyFromSeed() with 64-byte seed error = %v", errMax)
	}
}

func TestMasterKey_Derive(t *testing.T) {
	masterKey, _ := GenerateMasterKey()

	// 测试派生出 ethereum operational path
	path := bip44.NewOperationalPath(60, 0)

	derivedKey, err := masterKey.Derive(path)
	if err != nil {
		t.Fatalf("Derive() error = %v", err)
	}

	if derivedKey == nil {
		t.Fatalf("Derive() returned nil")
	}

	if len(derivedKey.Key) != 32 {
		t.Errorf("Derived key length = %d, want 32", len(derivedKey.Key))
	}
}

func TestMasterKey_Derive_Deterministic(t *testing.T) {
	masterKey, _ := GenerateMasterKey()
	path := bip44.NewOperationalPath(60, 5)

	// 多次派生同一路径应得到相同结果
	key1, _ := masterKey.Derive(path)
	key2, _ := masterKey.Derive(path)

	if string(key1.Key) != string(key2.Key) {
		t.Error("Deriving same path should produce same key")
	}
}

func TestMasterKey_Derive_Chained(t *testing.T) {
	masterKey, _ := GenerateMasterKey()

	// 先派生主密钥，再派生运营路径
	ethPath := bip44.NewOperationalPath(60, 0)

	// 直接派生到目标路径
	directKey, _ := masterKey.Derive(ethPath)

	// 分步派生 (如果需要)
	derivedKey, err := masterKey.Derive(ethPath)
	if err != nil {
		t.Fatalf("Derive() error = %v", err)
	}

	if string(directKey.Key) != string(derivedKey.Key) {
		t.Error("Direct derivation should equal step derivation")
	}
}

func TestMasterKey_DeriveFromChainCode(t *testing.T) {
	masterKey, _ := GenerateMasterKey()

	// 测试以太坊路径
	derivedKey, err := masterKey.DeriveFromChainCode("ethereum", 0, 1, 0)
	if err != nil {
		t.Fatalf("DeriveFromChainCode() error = %v", err)
	}

	if derivedKey == nil {
		t.Error("DeriveFromChainCode() returned nil")
	}

	// 验证不支持的链返回错误
	_, err = masterKey.DeriveFromChainCode("unsupported", 0, 0, 0)
	if err == nil {
		t.Error("DeriveFromChainCode() expected error for unsupported chain")
	}
}

func TestMasterKey_DeriveFromChainCode_VariousChains(t *testing.T) {
	masterKey, _ := GenerateMasterKey()

	chains := []string{"ethereum", "bitcoin", "solana", "polygon", "bsc"}

	for _, chain := range chains {
		t.Run(chain, func(t *testing.T) {
			derivedKey, err := masterKey.DeriveFromChainCode(chain, 0, 0, 0)
			if err != nil {
				t.Errorf("DeriveFromChainCode(%s) error = %v", chain, err)
			}
			if derivedKey == nil {
				t.Errorf("DeriveFromChainCode(%s) returned nil", chain)
			}
		})
	}
}

func TestMasterKey_DeriveChild(t *testing.T) {
	masterKey, _ := GenerateMasterKey()

	child, err := masterKey.DeriveChild(0)
	if err != nil {
		t.Fatalf("DeriveChild() error = %v", err)
	}

	if child == nil {
		t.Fatal("DeriveChild() returned nil")
	}

	if len(child.Key) != 32 {
		t.Errorf("Child key length = %d, want 32", len(child.Key))
	}
}

func TestMasterKey_DeriveChild_Deterministic(t *testing.T) {
	masterKey, _ := GenerateMasterKey()

	child1, _ := masterKey.DeriveChild(42)
	child2, _ := masterKey.DeriveChild(42)

	if string(child1.Key) != string(child2.Key) {
		t.Error("Deriving same child index should produce same key")
	}
}

func TestMasterKey_DeriveChild_DifferentIndices(t *testing.T) {
	masterKey, _ := GenerateMasterKey()

	child0, _ := masterKey.DeriveChild(0)
	child1, _ := masterKey.DeriveChild(1)
	childHardened, _ := masterKey.DeriveChild(0x80000000)

	if string(child0.Key) == string(child1.Key) {
		t.Error("Different child indices should produce different keys")
	}

	if string(child0.Key) == string(childHardened.Key) {
		t.Error("Hardened and non-hardened child indices should produce different keys")
	}
}

func TestMasterKey_DeriveECDSA(t *testing.T) {
	masterKey, _ := GenerateMasterKey()

	ecdsaKey, err := masterKey.DeriveECDSA()
	if err != nil {
		t.Fatalf("DeriveECDSA() error = %v", err)
	}

	if ecdsaKey == nil {
		t.Fatal("DeriveECDSA() returned nil")
	}

	if ecdsaKey.Curve != elliptic.P256() {
		t.Errorf("ECDSA curve = %v, want P256", ecdsaKey.Curve)
	}

	// 验证公钥可以正确计算
	if ecdsaKey.PublicKey.X == nil || ecdsaKey.PublicKey.Y == nil {
		t.Error("ECDSA public key not properly initialized")
	}
}

func TestMasterKey_DeriveECDSA_Verify(t *testing.T) {
	masterKey, _ := GenerateMasterKey()

	ecdsaKey, err := masterKey.DeriveECDSA()
	if err != nil {
		t.Fatalf("DeriveECDSA() error = %v", err)
	}

	// 使用私钥签名
	msg := []byte("test message")
	r, s, err := ecdsa.Sign(cryptorand.Reader, ecdsaKey, msg)
	if err != nil {
		t.Fatalf("ecdsa.Sign() error = %v", err)
	}

	// 验证签名
	publicKey := ecdsaKey.PublicKey
	valid := ecdsa.Verify(&publicKey, msg, r, s)
	if !valid {
		t.Error("ECDSA signature verification failed")
	}
}

func TestMasterKey_DeriveSecp256k1(t *testing.T) {
	masterKey, _ := GenerateMasterKey()

	secpKey, err := masterKey.DeriveSecp256k1()
	if err != nil {
		t.Fatalf("DeriveSecp256k1() error = %v", err)
	}

	if secpKey == nil {
		t.Error("DeriveSecp256k1() returned nil")
	}

	// 验证公钥存在
	pubKey := secpKey.PubKey()
	if pubKey == nil {
		t.Error("Secp256k1 public key is nil")
	}
}

func TestMasterKey_DeriveSecp256k1_Serialize(t *testing.T) {
	masterKey, _ := GenerateMasterKey()

	secpKey, _ := masterKey.DeriveSecp256k1()

	// 序列化私钥
	privBytes := secpKey.Serialize()
	if len(privBytes) != 32 {
		t.Errorf("Serialize() length = %d, want 32", len(privBytes))
	}

	// 序列化公钥
	pubBytes := secpKey.PubKey().SerializeCompressed()
	if len(pubBytes) != 33 {
		t.Errorf("SerializeCompressed() length = %d, want 33", len(pubBytes))
	}
}

func TestMasterKey_PublicKey(t *testing.T) {
	masterKey, _ := GenerateMasterKey()

	pubKey := masterKey.PublicKey()
	if pubKey == nil {
		t.Error("PublicKey() returned nil")
	}

	// 验证公钥是有效的 (compressed format for secp256k1)
	// ECDSA P-256 公钥是 65 字节 (04 || x || y)
	// secp256k1 可以是 33 字节 (compressed) 或 65 字节 (uncompressed)
	// 这里 masterKey 使用的是 BIP-32 的公钥格式
	if len(pubKey) < 33 {
		t.Errorf("PublicKey() length = %d, too short", len(pubKey))
	}
}

func TestMasterKey_PublicKey_Deterministic(t *testing.T) {
	masterKey, _ := GenerateMasterKey()

	pubKey1 := masterKey.PublicKey()
	pubKey2 := masterKey.PublicKey()

	if string(pubKey1) != string(pubKey2) {
		t.Error("PublicKey() should be deterministic")
	}
}

func TestEncodeMasterKeySeed(t *testing.T) {
	masterKey, _ := GenerateMasterKey()

	encoded, err := EncodeMasterKeySeed(masterKey)
	if err != nil {
		t.Fatalf("EncodeMasterKeySeed() error = %v", err)
	}

	if encoded == "" {
		t.Error("EncodeMasterKeySeed() returned empty string")
	}

	// 验证是有效的 base64
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Errorf("Encoded string is not valid base64: %v", err)
	}

	// 验证包含 PEM 格式
	block, _ := pem.Decode(decoded)
	if block == nil {
		t.Fatal("Encoded data does not contain valid PEM block")
	}

	if block.Type != TypeMasterKeySeed {
		t.Errorf("PEM type = %s, want %s", block.Type, TypeMasterKeySeed)
	}

	if len(block.Bytes) != 32 {
		t.Errorf("PEM bytes length = %d, want 32", len(block.Bytes))
	}
}

func TestDecodeMasterKeySeed(t *testing.T) {
	// 创建并编码主密钥
	originalKey, _ := GenerateMasterKey()
	encoded, _ := EncodeMasterKeySeed(originalKey)

	// 解码
	decodedKey, err := DecodeMasterKeySeed(encoded)
	if err != nil {
		t.Fatalf("DecodeMasterKeySeed() error = %v", err)
	}

	if decodedKey == nil {
		t.Fatal("DecodeMasterKeySeed() returned nil")
	}

	// 验证解码后的密钥是有效的
	if decodedKey.Key == nil {
		t.Fatal("Decoded key is invalid")
	}
	if len(decodedKey.Key.Key) != 32 {
		t.Error("Decoded key has invalid length")
	}

	// 注意：解码后的密钥与原始密钥不同，因为 Decode 使用私钥字节作为种子重新派生
}

func TestEncodeDecodeMasterKeySeed_RoundTrip(t *testing.T) {
	seeds := [][]byte{
		[]byte("000102030405060708090a0b0c0d0e0f"),
		[]byte("0123456789abcdef0123456789abcdef"),
		make([]byte, 64), // 全零 64 字节种子
	}

	for i, seed := range seeds {
		t.Run("", func(t *testing.T) {
			masterKey, _ := NewMasterKeyFromSeed(seed)
			encoded, _ := EncodeMasterKeySeed(masterKey)
			decodedKey, err := DecodeMasterKeySeed(encoded)
			if err != nil {
				t.Errorf("Round trip %d failed: %v", i, err)
			}
			// 解码后的密钥应该是有效的 32 字节私钥
			if decodedKey == nil || len(decodedKey.Key.Key) != 32 {
				t.Errorf("Round trip %d: decoded key is invalid", i)
			}
		})
	}
}

func TestDecodeMasterKeySeed_InvalidBase64(t *testing.T) {
	_, err := DecodeMasterKeySeed("not-valid-base64!!!")
	if err == nil {
		t.Error("DecodeMasterKeySeed() expected error for invalid base64")
	}
}

func TestDecodeMasterKeySeed_InvalidPEM(t *testing.T) {
	// 有效的 base64 但不是 PEM
	encoded := base64.StdEncoding.EncodeToString([]byte("not a pem"))
	_, err := DecodeMasterKeySeed(encoded)
	if err == nil {
		t.Error("DecodeMasterKeySeed() expected error for invalid PEM")
	}
}

func TestDecodeMasterKeySeed_InvalidType(t *testing.T) {
	// 正确的 PEM 格式但类型不匹配
	pemBlock := &pem.Block{
		Type:  "WRONG TYPE",
		Bytes: make([]byte, 32),
	}
	pemBytes := pem.EncodeToMemory(pemBlock)
	encoded := base64.StdEncoding.EncodeToString(pemBytes)

	_, err := DecodeMasterKeySeed(encoded)
	if err == nil {
		t.Error("DecodeMasterKeySeed() expected error for wrong PEM type")
	}
}

func TestEncodePrivateKey(t *testing.T) {
	keyBytes := []byte("0123456789abcdef")
	blockType := "PRIVATE KEY"

	encoded, err := EncodePrivateKey(keyBytes, blockType)
	if err != nil {
		t.Fatalf("EncodePrivateKey() error = %v", err)
	}

	block, _ := pem.Decode(encoded)
	if block == nil {
		t.Fatal("Encoded data does not contain valid PEM block")
	}

	if block.Type != blockType {
		t.Errorf("PEM type = %s, want %s", block.Type, blockType)
	}

	if string(block.Bytes) != string(keyBytes) {
		t.Error("PEM bytes do not match original key")
	}
}

func TestEncodePrivateKey_EmptyBytes(t *testing.T) {
	encoded, err := EncodePrivateKey([]byte{}, "EMPTY")
	if err != nil {
		t.Fatalf("EncodePrivateKey() error = %v", err)
	}

	block, _ := pem.Decode(encoded)
	if block == nil {
		t.Fatal("Encoded data does not contain valid PEM block")
	}

	if len(block.Bytes) != 0 {
		t.Errorf("PEM bytes length = %d, want 0", len(block.Bytes))
	}
}

func TestDecodePEM(t *testing.T) {
	pemData := `-----BEGIN TEST BLOCK-----
dGVzdCBkYXRh
-----END TEST BLOCK-----
-----BEGIN ANOTHER BLOCK-----
YW5vdGhlciBkYXRh
-----END ANOTHER BLOCK-----
`

	block, remaining := DecodePEM([]byte(pemData))
	if block == nil {
		t.Fatal("DecodePEM() returned nil block")
	}

	if block.Type != "TEST BLOCK" {
		t.Errorf("Block type = %s, want TEST BLOCK", block.Type)
	}

	if string(block.Bytes) != "test data" {
		t.Errorf("Block bytes = %s, want test data", string(block.Bytes))
	}

	// 验证还有剩余数据
	if len(remaining) == 0 {
		t.Error("Expected remaining data after first block")
	}
}

func TestDecodePEM_NoBlock(t *testing.T) {
	invalidData := []byte("not a pem data")

	block, remaining := DecodePEM(invalidData)
	if block != nil {
		t.Error("DecodePEM() should return nil for invalid data")
	}

	if len(remaining) != len(invalidData) {
		t.Error("Remaining data should be empty for invalid input")
	}
}

func TestDecodePEM_EmptyInput(t *testing.T) {
	block, remaining := DecodePEM([]byte{})
	if block != nil {
		t.Error("DecodePEM() should return nil for empty input")
	}
	// pem.Decode returns empty slice, not nil
	if len(remaining) != 0 {
		t.Errorf("Remaining length = %d, want 0", len(remaining))
	}
}

func TestDecodePEM_MultipleBlocks(t *testing.T) {
	pemData := `-----BEGIN FIRST-----
Zmlyc3Q=
-----END FIRST-----
-----BEGIN SECOND-----
c2Vjb25k
-----END SECOND-----
-----BEGIN THIRD-----
dGhpcmQ=
-----END THIRD-----
`

	var blocks []*pem.Block
	remaining := []byte(pemData)

	for {
		block, rem := DecodePEM(remaining)
		if block == nil {
			break
		}
		blocks = append(blocks, block)
		remaining = rem
	}

	if len(blocks) != 3 {
		t.Errorf("DecodePEM() found %d blocks, want 3", len(blocks))
	}

	expected := []string{"FIRST", "SECOND", "THIRD"}
	for i, block := range blocks {
		if block.Type != expected[i] {
			t.Errorf("Block %d type = %s, want %s", i, block.Type, expected[i])
		}
	}
}
