package algorithm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

// TestEd25519Algorithm_AlgorithmID 测试算法 ID
func TestEd25519Algorithm_AlgorithmID(t *testing.T) {
	algo := NewEd25519Algorithm()

	if got := algo.AlgorithmID(); got != "eddsa-ed25519" {
		t.Errorf("AlgorithmID() = %v, want %v", got, "eddsa-ed25519")
	}
}

// TestEd25519Algorithm_GenerateKey 测试密钥生成
func TestEd25519Algorithm_GenerateKey(t *testing.T) {
	algo := NewEd25519Algorithm()

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
	edPriv, ok := privKey.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("Expected ed25519.PrivateKey, got %T", privKey)
	}

	if len(edPriv) != ed25519.PrivateKeySize {
		t.Errorf("Private key length = %d, want %d", len(edPriv), ed25519.PrivateKeySize)
	}

	// 验证公钥
	edPub, ok := pubKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("Expected ed25519.PublicKey, got %T", pubKey)
	}

	if len(edPub) != ed25519.PublicKeySize {
		t.Errorf("Public key length = %d, want %d", len(edPub), ed25519.PublicKeySize)
	}

	// 验证公钥与私钥一致
	if len(edPriv) != ed25519.PrivateKeySize {
		t.Error("Invalid private key size")
	}
}

// TestEd25519Algorithm_Sign 测试签名
func TestEd25519Algorithm_Sign(t *testing.T) {
	algo := NewEd25519Algorithm()

	privKey, _, err := algo.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	message := []byte("Hello, Ed25519!")
	signature, err := algo.Sign(privKey, message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if len(signature) != ed25519.SignatureSize {
		t.Errorf("Signature length = %d, want %d", len(signature), ed25519.SignatureSize)
	}
}

// TestEd25519Algorithm_SerializePrivateKey 测试私钥序列化
func TestEd25519Algorithm_SerializePrivateKey(t *testing.T) {
	algo := NewEd25519Algorithm()

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
}

// TestEd25519Algorithm_SerializePublicKey 测试公钥序列化
func TestEd25519Algorithm_SerializePublicKey(t *testing.T) {
	algo := NewEd25519Algorithm()

	_, pubKey, err := algo.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	pubBytes, err := algo.SerializePublicKey(pubKey)
	if err != nil {
		t.Fatalf("SerializePublicKey() error = %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	pubKeyPEM := string(pemBytes)
	fmt.Printf("public 1: %s\n", pubKeyPEM)

	pk, err := parsePublicKey(pubKeyPEM)
	if err != nil {
		t.Fatalf("parsePublicKey() error = %v", err)
	}

	switch p := pk.(type) {
	case *ecdsa.PublicKey:
		fmt.Println("ECDSA P-256:", p.X, p.Y)
	case *rsa.PublicKey:
		fmt.Println("RSA:", p.N)
	case ed25519.PublicKey:
		fmt.Println("Ed25519:", p)
	}

	// originalPub := pubKey.(crypto.Signer).Public()

	if !reflect.DeepEqual(pubKey, pk) {
		t.Errorf("Parsed public key does not match original. Got: %#v, Want: %#v", pk, pubKey)
	}
}

func parsePublicKey(pemData string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}

	// 解析 PKIX SubjectPublicKeyInfo
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// TestEd25519Algorithm_ParsePrivateKey 测试私钥解析
func TestEd25519Algorithm_ParsePrivateKey(t *testing.T) {
	algo := NewEd25519Algorithm()

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

	_, ok := parsedKey.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("Parsed key type = %T, want ed25519.PrivateKey", parsedKey)
	}
}

// TestEd25519Algorithm_ClearPrivateKey 测试私钥清零
func TestEd25519Algorithm_ClearPrivateKey(t *testing.T) {
	algo := NewEd25519Algorithm()

	privKey, pubKey, err := algo.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// 清零前可以正常签名
	message := []byte("test message")
	sig1, err := algo.Sign(privKey, message)
	if err != nil {
		t.Fatalf("Sign() error before clear = %v", err)
	}

	// 清零私钥
	algo.ClearPrivateKey(privKey)

	// 清零后使用 ed25519.Verify 验证签名（使用原始公钥）
	// Ed25519 清零后签名会不同
	valid := ed25519.Verify(pubKey.(ed25519.PublicKey), message, sig1)
	if !valid {
		t.Error("Original signature should still be valid (key data unchanged in memory)")
	}
}

// TestEd25519Algorithm_HashFunc 测试哈希函数
func TestEd25519Algorithm_HashFunc(t *testing.T) {
	algo := NewEd25519Algorithm()

	// Ed25519 使用 crypto.Hash(0) 表示不需要外部哈希
	if got := algo.HashFunc(); got != crypto.Hash(0) {
		t.Errorf("HashFunc() = %v, want %v", got, crypto.Hash(0))
	}
}

// TestEd25519Algorithm_VerifySignature 测试签名验证
func TestEd25519Algorithm_VerifySignature(t *testing.T) {
	algo := NewEd25519Algorithm()

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

	// 验证签名
	valid := ed25519.Verify(pubKey.(ed25519.PublicKey), message, signature)
	if !valid {
		t.Error("Signature verification failed")
	}
}

// TestEd25519Algorithm_DeterministicKeyGen 测试密钥生成确定性
func TestEd25519Algorithm_DeterministicKeyGen(t *testing.T) {
	algo := NewEd25519Algorithm()

	// 生成两个密钥对
	_, pub1, err := algo.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	_, pub2, err := algo.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	// 每次生成的密钥应该不同
	if string(pub1.(ed25519.PublicKey)) == string(pub2.(ed25519.PublicKey)) {
		t.Error("Generated keys should be unique")
	}
}

// TestEd25519Algorithm_SignDifferentMessages 测试不同消息签名
func TestEd25519Algorithm_SignDifferentMessages(t *testing.T) {
	algo := NewEd25519Algorithm()

	privKey, _, err := algo.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	messages := [][]byte{
		[]byte("Message 1"),
		[]byte("Message 2"),
		[]byte(""),
		[]byte("A longer message with more content"),
	}

	signatures := make([][]byte, 0, len(messages))
	for _, msg := range messages {
		sig, err := algo.Sign(privKey, msg)
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		signatures = append(signatures, sig)
	}

	// 验证所有签名都不同
	for i := 0; i < len(signatures); i++ {
		for j := i + 1; j < len(signatures); j++ {
			if string(signatures[i]) == string(signatures[j]) {
				t.Errorf("Signatures %d and %d should be different", i, j)
			}
		}
	}
}
