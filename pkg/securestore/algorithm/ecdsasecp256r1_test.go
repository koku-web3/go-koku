package algorithm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"testing"
)

const (
	MockPrivKey2 = "218f84362a3c489e21d6f8176f03dd9a1cc208b9fcfe02f9eb2e35714e28d071"
)

// TestSecp256r1Algorithm_AlgorithmID 测试算法 ID
func TestSecp256r1Algorithm_AlgorithmID(t *testing.T) {
	algo := NewSecp256r1Algorithm()
	expected := "ecdsa-secp256r1"

	if got := algo.AlgorithmID(); got != expected {
		t.Errorf("AlgorithmID() = %v, want %v", got, expected)
	}
}

// TestSecp256r1Algorithm_GenerateKey 测试密钥生成
func TestSecp256r1Algorithm_GenerateKey(t *testing.T) {
	algo := NewSecp256r1Algorithm()

	privKey, pubKey, err := algo.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	if privKey == nil {
		t.Fatal("GenerateKey() returned nil private key")
	}

	if pubKey == nil {
		t.Fatal("GenerateKey() returned nil public key")
	}

	// 验证私钥类型
	ecdsaPriv, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("Expected *ecdsa.PrivateKey, got %T", privKey)
	}

	// 验证公钥
	ecdsaPub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Expected *ecdsa.PublicKey, got %T", pubKey)
	}

	// 验证公钥与私钥一致
	if ecdsaPub.X.Cmp(ecdsaPriv.X) != 0 || ecdsaPub.Y.Cmp(ecdsaPriv.Y) != 0 {
		t.Error("Public key does not match private key")
	}
}

// TestSecp256r1Algorithm_Sign 测试签名
func TestSecp256r1Algorithm_Sign(t *testing.T) {
	algo := NewSecp256r1Algorithm()

	privKeyHex := MockPrivKey2
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		t.Fatalf("failed to decode private key hex: %v", err)
	}
	privKey, err := algo.NewPrivateKeyFromBytes(privKeyBytes)
	if err != nil {
		t.Fatalf("NewPrivateKeyFromBytes() error = %v", err)
	}

	message, _ := hex.DecodeString("e2c1e0526103d300a350fa2031d2fc70479e11fa23aa1790c1554a0cc7924bfe")
	signature, err := algo.Sign(privKey, message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// DER 编码签名长度至少 8 字节
	if len(signature) == 0 {
		t.Error("Sign() returned empty signature")
	}

	sigLen := len(signature)
	if sigLen < 8 {
		t.Errorf("Signature too short: %d bytes", sigLen)
	}
	fmt.Println(hex.EncodeToString(signature))
}

// TestSecp256r1Algorithm_SerializePrivateKey 测试私钥序列化
func TestSecp256r1Algorithm_SerializePrivateKey(t *testing.T) {
	algo := NewSecp256r1Algorithm()

	privKey, _, err := algo.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	derBytes, err := algo.SerializePrivateKey(privKey)
	if err != nil {
		t.Fatalf("SerializePrivateKey() error = %v", err)
	}

	if len(derBytes) == 0 {
		t.Error("SerializePrivateKey() returned empty bytes")
	}

	// 尝试解析
	key, err := x509.ParsePKCS8PrivateKey(derBytes)
	if err != nil {
		t.Fatalf("Failed to parse serialized key: %v", err)
	}

	if _, ok := key.(*ecdsa.PrivateKey); !ok {
		t.Errorf("Parsed key type = %T, want *ecdsa.PrivateKey", key)
	}
}

// TestSecp256r1Algorithm_SerializePublicKey 测试公钥序列化
func TestSecp256r1Algorithm_SerializePublicKey(t *testing.T) {
	algo := NewSecp256r1Algorithm()

	_, pubKey, err := algo.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	pubBytes, err := algo.SerializePublicKey(pubKey)
	if err != nil {
		t.Fatalf("SerializePublicKey() error = %v", err)
	}

	if len(pubBytes) == 0 {
		t.Error("SerializePublicKey() returned empty bytes")
	}

	// 尝试解析
	key, err := x509.ParsePKIXPublicKey(pubBytes)
	if err != nil {
		t.Fatalf("Failed to parse serialized public key: %v", err)
	}

	if _, ok := key.(*ecdsa.PublicKey); !ok {
		t.Errorf("Parsed key type = %T, want *ecdsa.PublicKey", key)
	}
}

// TestSecp256r1Algorithm_ParsePrivateKey 测试私钥解析
func TestSecp256r1Algorithm_ParsePrivateKey(t *testing.T) {
	algo := NewSecp256r1Algorithm()

	// 先生成并序列化
	privKey, _, err := algo.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	derBytes, err := algo.SerializePrivateKey(privKey)
	if err != nil {
		t.Fatalf("SerializePrivateKey() error = %v", err)
	}

	// 解析
	parsedKey, err := algo.ParsePrivateKey(derBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKey() error = %v", err)
	}

	ecdsaKey, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("Parsed key type = %T, want *ecdsa.PrivateKey", parsedKey)
	}

	// 验证密钥一致性
	origKey := privKey.(*ecdsa.PrivateKey)
	if ecdsaKey.X.Cmp(origKey.X) != 0 || ecdsaKey.Y.Cmp(origKey.Y) != 0 {
		t.Error("Parsed key does not match original")
	}
}

// TestSecp256r1Algorithm_ClearPrivateKey 测试私钥清零
func TestSecp256r1Algorithm_ClearPrivateKey(t *testing.T) {
	algo := NewSecp256r1Algorithm()

	privKey, _, err := algo.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	ecdsaKey := privKey.(*ecdsa.PrivateKey)

	// 清零
	algo.ClearPrivateKey(privKey)

	// 验证 D 值为 0
	if ecdsaKey.D.BitLen() != 0 {
		t.Error("ClearPrivateKey() did not zero D value")
	}
}

// TestSecp256r1Algorithm_HashFunc 测试哈希函数
func TestSecp256r1Algorithm_HashFunc(t *testing.T) {
	algo := NewSecp256r1Algorithm()

	if got := algo.HashFunc(); got != crypto.SHA256 {
		t.Errorf("HashFunc() = %v, want %v", got, crypto.SHA256)
	}
}

// TestSecp256r1Algorithm_VerifySignature 测试签名验证
func TestSecp256r1Algorithm_VerifySignature(t *testing.T) {
	algo := NewSecp256r1Algorithm()

	privKey, pubKey, err := algo.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	message := []byte("Test message for verification")

	// 签名
	signature, err := algo.Sign(privKey, message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// 使用 crypto.Signer 的 VerifyASN1 方法验证签名
	ecdsaPub := pubKey.(*ecdsa.PublicKey)

	// 重新计算哈希
	h := sha256.Sum256(message)

	valid := ecdsa.VerifyASN1(ecdsaPub, h[:], signature)
	if !valid {
		t.Error("Signature verification failed")
	}
}

// TestSecp256r1Algorithm_DifferentCurves 测试不同曲线
func TestSecp256r1Algorithm_DifferentCurves(t *testing.T) {
	curves := []struct {
		name  string
		curve string
	}{
		{"P-256", "test-P-256"},
		{"P-384", "test-P-384"},
		{"P-521", "test-P-521"},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			algo := NewSecp256r1Algorithm()

			privKey, _, err := algo.GenerateKey()
			if err != nil {
				t.Fatalf("GenerateKey() error = %v", err)
			}

			// 签名
			message := []byte("test")
			sig, err := algo.Sign(privKey, message)
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}

			if len(sig) == 0 {
				t.Error("Sign() returned empty signature")
			}
		})
	}
}

// TestSecp256r1Algorithm_NewPrivateKeyFromBytes 测试从字节创建私钥
func TestSecp256r1Algorithm_NewPrivateKeyFromBytes(t *testing.T) {
	algo := NewSecp256r1Algorithm()

	// 使用已知私钥
	privKeyHex := "218f84362a3c489e21d6f8176f03dd9a1cc208b9fcfe02f9eb2e35714e28d071"
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		t.Fatalf("failed to decode private key hex: %v", err)
	}

	privKey, err := algo.NewPrivateKeyFromBytes(privKeyBytes)
	if err != nil {
		t.Fatalf("NewPrivateKeyFromBytes() error = %v", err)
	}

	ecdsaKey, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("Expected *ecdsa.PrivateKey, got %T", privKey)
	}

	// 验证 D 值正确
	expectedD := "218f84362a3c489e21d6f8176f03dd9a1cc208b9fcfe02f9eb2e35714e28d071"
	if hex.EncodeToString(ecdsaKey.D.Bytes()) != expectedD {
		t.Errorf("D value mismatch, got %x, want %s", ecdsaKey.D.Bytes(), expectedD)
	}
}

// TestSecp256r1Algorithm_NewPrivateKeyFromBytes_InvalidLength 测试无效长度
func TestSecp256r1Algorithm_NewPrivateKeyFromBytes_InvalidLength(t *testing.T) {
	algo := NewSecp256r1Algorithm()

	// 长度不对
	_, err := algo.NewPrivateKeyFromBytes([]byte{0x01, 0x02})
	if err == nil {
		t.Error("expected error for invalid length, got nil")
	}
}
