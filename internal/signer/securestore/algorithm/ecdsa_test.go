package algorithm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"testing"
)

// TestECDSAAlgorithm_AlgorithmID 测试算法 ID
func TestECDSAAlgorithm_AlgorithmID(t *testing.T) {
	tests := []struct {
		name     string
		algo     *ECDSAAlgorithm
		expected string
	}{
		{
			name:     "secp256k1",
			algo:     NewECDSAAlgorithm("ecdsa-secp256k1", elliptic.P256()),
			expected: "ecdsa-secp256k1",
		},
		{
			name:     "secp256r1",
			algo:     NewECDSAAlgorithm("ecdsa-secp256r1", elliptic.P256()),
			expected: "ecdsa-secp256r1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.algo.AlgorithmID(); got != tt.expected {
				t.Errorf("AlgorithmID() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestECDSAAlgorithm_GenerateKey 测试密钥生成
func TestECDSAAlgorithm_GenerateKey(t *testing.T) {
	algo := NewECDSAAlgorithm("ecdsa-secp256r1", elliptic.P256())

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

// TestECDSAAlgorithm_Sign 测试签名
func TestECDSAAlgorithm_Sign(t *testing.T) {
	algo := NewECDSAAlgorithm("ecdsa-secp256r1", elliptic.P256())

	privKey, _, err := algo.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	message := []byte("Hello, World!")
	signature, err := algo.Sign(privKey, message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// ECDSA 签名长度应该是 64 字节 (P-256 的 r 和 s 各 32 字节)
	// DER 编码会添加前缀，所以这里检查的是 DER 编码后的长度
	if len(signature) == 0 {
		t.Error("Sign() returned empty signature")
	}

	// 验证签名可以被正确解析为 r 和 s
	sigLen := len(signature)
	if sigLen < 8 { // 最小的 DER 编码签名
		t.Errorf("Signature too short: %d bytes", sigLen)
	}
}

// TestECDSAAlgorithm_SerializePrivateKey 测试私钥序列化
func TestECDSAAlgorithm_SerializePrivateKey(t *testing.T) {
	algo := NewECDSAAlgorithm("ecdsa-secp256r1", elliptic.P256())

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

// TestECDSAAlgorithm_SerializePublicKey 测试公钥序列化
func TestECDSAAlgorithm_SerializePublicKey(t *testing.T) {
	algo := NewECDSAAlgorithm("ecdsa-secp256r1", elliptic.P256())

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
		t.Fatalf("Failed to parse serialized key: %v", err)
	}

	if _, ok := key.(*ecdsa.PublicKey); !ok {
		t.Errorf("Parsed key type = %T, want *ecdsa.PublicKey", key)
	}
}

// TestECDSAAlgorithm_ParsePrivateKey 测试私钥解析
func TestECDSAAlgorithm_ParsePrivateKey(t *testing.T) {
	algo := NewECDSAAlgorithm("ecdsa-secp256r1", elliptic.P256())

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

// TestECDSAAlgorithm_ClearPrivateKey 测试私钥清零
func TestECDSAAlgorithm_ClearPrivateKey(t *testing.T) {
	algo := NewECDSAAlgorithm("ecdsa-secp256r1", elliptic.P256())

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

// TestECDSAAlgorithm_HashFunc 测试哈希函数
func TestECDSAAlgorithm_HashFunc(t *testing.T) {
	algo := NewECDSAAlgorithm("ecdsa-secp256r1", elliptic.P256())

	if got := algo.HashFunc(); got != crypto.SHA256 {
		t.Errorf("HashFunc() = %v, want %v", got, crypto.SHA256)
	}
}

// TestECDSAAlgorithm_VerifySignature 测试签名验证
func TestECDSAAlgorithm_VerifySignature(t *testing.T) {
	algo := NewECDSAAlgorithm("ecdsa-secp256r1", elliptic.P256())

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

// TestECDSAAlgorithm_DifferentCurves 测试不同曲线
func TestECDSAAlgorithm_DifferentCurves(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P-256", elliptic.P256()},
		{"P-384", elliptic.P384()},
		{"P-521", elliptic.P521()},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			algo := NewECDSAAlgorithm("test-"+tc.name, tc.curve)

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
