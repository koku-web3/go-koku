package securestore

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

// TestMemzero 测试内存清零功能
func TestMemzero(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	originalLen := len(data)

	// 调用 Memzero
	Memzero(data)

	// 验证所有字节都被清零
	for i, b := range data {
		if b != 0 {
			t.Errorf("Byte at index %d was not zeroed: expected 0, got %d", i, b)
		}
	}

	// 验证切片长度不变
	if len(data) != originalLen {
		t.Errorf("Slice length changed: expected %d, got %d", originalLen, len(data))
	}
}

// TestSecureBytes 测试安全字节切片
func TestSecureBytes(t *testing.T) {
	original := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	// 创建安全字节
	sb := NewSecureBytes(original)

	// 验证返回的字节内容正确
	result := sb.Bytes()
	if !bytes.Equal(result, original) {
		t.Errorf("Bytes() returned wrong data")
	}

	// 验证原始数据未被修改
	if original[0] != 0xDE {
		t.Errorf("Original data was modified")
	}

	// 清零
	sb.Clear()

	// 验证清零后数据为 nil
	if sb.data != nil {
		t.Errorf("Data should be nil after Clear()")
	}
}

// TestSecureString 测试安全字符串
func TestSecureString(t *testing.T) {
	original := "sensitive-password-12345"

	ss := NewSecureString(original)

	// 验证返回的字符串正确
	if ss.String() != original {
		t.Errorf("String() returned wrong value")
	}

	// 清零
	ss.Clear()

	// 验证清零后为 nil
	if ss.chars != nil {
		t.Errorf("Chars should be nil after Clear()")
	}
}

// TestSecurePrivateKey_Clear 测试私钥清零
func TestSecurePrivateKey_Clear(t *testing.T) {
	// 生成测试用 ECDSA 私钥
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// 序列化为 DER 格式
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("Failed to marshal key: %v", err)
	}

	// 创建安全私钥
	spk := NewSecurePrivateKey(priv, privBytes, "ecdsa-secp256r1")

	// 验证可以获取密钥
	if spk.Key() == nil {
		t.Errorf("Key() returned nil before Clear()")
	}

	// 清零
	spk.Clear()

	// 验证清零后状态
	if !spk.IsCleared() {
		t.Errorf("IsCleared() should return true after Clear()")
	}

	if spk.Key() != nil {
		t.Errorf("Key() should return nil after Clear()")
	}
}

// TestSecurePrivateKey_ParseFromBase64 测试从 Base64 解析私钥
func TestSecurePrivateKey_ParseFromBase64(t *testing.T) {
	// 生成测试用 ECDSA 私钥
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// 序列化为 DER 格式
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("Failed to marshal key: %v", err)
	}

	// 包装为 PEM 格式
	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	// 转换为 Base64
	base64Data := base64.StdEncoding.EncodeToString(pemBytes)

	// 解析
	spk, err := ParsePrivateKeyFromBase64(base64Data, "ecdsa-secp256r1")
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	// 验证可以获取密钥
	if spk.Key() == nil {
		t.Errorf("Key() returned nil")
	}

	// 验证密钥类型
	_, ok := spk.Key().(*ecdsa.PrivateKey)
	if !ok {
		t.Errorf("Key should be *ecdsa.PrivateKey")
	}

	// 清零
	spk.Clear()
}

// TestParsePrivateKeyFromBase64_InvalidData 测试无效数据解析
func TestParsePrivateKeyFromBase64_InvalidData(t *testing.T) {
	testCases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "invalid base64",
			input:   "not-valid-base64!!!",
			wantErr: true,
		},
		{
			name:    "valid base64 but invalid PEM",
			input:   base64.StdEncoding.EncodeToString([]byte("not a PEM")),
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParsePrivateKeyFromBase64(tc.input, "ecdsa-secp256r1")
			if (err != nil) != tc.wantErr {
				t.Errorf("ParsePrivateKeyFromBase64() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestSecureSigner 测试安全签名器
func TestSecureSigner(t *testing.T) {
	// 生成测试用 ECDSA 私钥
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// 序列化为 DER 格式
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("Failed to marshal key: %v", err)
	}

	// 创建安全私钥
	spk := NewSecurePrivateKey(priv, privBytes, "ecdsa-secp256r1")

	// 创建安全签名器
	ss := NewSecureSigner(spk)

	// 待签名的消息
	message := []byte("test message for signing")

	// 签名
	signature, err := ss.Sign(message, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}

	if len(signature) == 0 {
		t.Errorf("Signature should not be empty")
	}

	// 验证私钥已被清零（因为签名后自动清零）
	if !spk.IsCleared() {
		t.Errorf("Private key should be cleared after Sign()")
	}
}

// TestGenerateSecureRandom 测试安全随机数生成
func TestGenerateSecureRandom(t *testing.T) {
	// 生成随机字节
	secureBytes, err := GenerateSecureRandom(32)
	if err != nil {
		t.Fatalf("GenerateSecureRandom() failed: %v", err)
	}

	// 验证长度
	if len(secureBytes.Bytes()) != 32 {
		t.Errorf("Expected 32 bytes, got %d", len(secureBytes.Bytes()))
	}

	// 验证生成了不同的随机数
	secureBytes2, err := GenerateSecureRandom(32)
	if err != nil {
		t.Fatalf("GenerateSecureRandom() failed: %v", err)
	}

	if bytes.Equal(secureBytes.Bytes(), secureBytes2.Bytes()) {
		t.Errorf("Two random generations should not be equal")
	}

	// 清零
	secureBytes.Clear()
	secureBytes2.Clear()
}

// TestClearIdempotence 测试 Clear 的幂等性
func TestClearIdempotence(t *testing.T) {
	// 生成测试用私钥
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("Failed to marshal key: %v", err)
	}

	spk := NewSecurePrivateKey(priv, privBytes, "ecdsa-secp256r1")

	// 第一次清零
	spk.Clear()

	// 第二次清零不应该 panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("Clear() panicked on second call: %v", r)
		}
	}()
	spk.Clear()
}

// BenchmarkMemzero 性能测试
func BenchmarkMemzero(b *testing.B) {
	data := make([]byte, 1024)
	for i := 0; i < b.N; i++ {
		Memzero(data)
	}
}

// BenchmarkSecurePrivateKey_Clear 性能测试
func BenchmarkSecurePrivateKey_Clear(b *testing.B) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privBytes, _ := x509.MarshalPKCS8PrivateKey(priv)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		spk := NewSecurePrivateKey(priv, privBytes, "ecdsa-secp256r1")
		spk.Clear()
	}
}

// TestEd25519Clear 测试 Ed25519 私钥清零
func TestEd25519Clear(t *testing.T) {
	// Ed25519 私钥实际上是 [64]byte 类型
	// 创建一个模拟的 ed25519 私钥用于测试
	seed := make([]byte, 32)
	_, _ = rand.Read(seed)
	defer Memzero(seed)

	// 使用 seed 创建 ed25519 私钥
	priv := ed25519.NewKeyFromSeed(seed)

	// 创建安全私钥包装
	spk := &SecurePrivateKey{
		key:         priv,
		keyBytes:    priv,
		algorithmID: "eddsa-ed25519",
	}

	// 清零
	spk.Clear()

	if !spk.IsCleared() {
		t.Errorf("Ed25519 key should be cleared")
	}
}
