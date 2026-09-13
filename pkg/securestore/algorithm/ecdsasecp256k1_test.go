package algorithm

import (
	"crypto"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

const (
	MockPrivKey1 = "218f84362a3c489e21d6f8176f03dd9a1cc208b9fcfe02f9eb2e35714e28d071"
)

// TestSecp256k1Algorithm_AlgorithmID 测试算法 ID
func TestSecp256k1Algorithm_AlgorithmID(t *testing.T) {
	algo := NewSecp256k1Algorithm()
	expected := "ecdsa-secp256k1"
	if got := algo.AlgorithmID(); got != expected {
		t.Errorf("AlgorithmID() = %v, want %v", got, expected)
	}
}

// TestSecp256k1Algorithm_GenerateKey 测试密钥生成
func TestSecp256k1Algorithm_GenerateKey(t *testing.T) {
	algo := NewSecp256k1Algorithm()
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

	// 验证类型
	sk, ok := privKey.(*secpPrivKey)
	if !ok {
		t.Fatalf("Expected *secpPrivKey, got %T", privKey)
	}
	if sk.priv == nil {
		t.Fatal("secpPrivKey.priv is nil")
	}

	btcPub, ok := pubKey.(*btcec.PublicKey)
	if !ok {
		t.Fatalf("Expected *btcec.PublicKey, got %T", pubKey)
	}

	// 验证公钥一致
	if !sk.PubKey().IsEqual(btcPub) {
		t.Error("Public key does not match private key")
	}
}

// TestSecp256k1Algorithm_NewPrivateKeyFromBytes 测试从字节创建私钥
func TestSecp256k1Algorithm_NewPrivateKeyFromBytes(t *testing.T) {
	algo := NewSecp256k1Algorithm()
	privKeyHex := MockPrivKey1
	privKeyBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		t.Fatalf("failed to decode private key hex: %v", err)
	}
	privKey, err := algo.NewPrivateKeyFromBytes(privKeyBytes)
	if err != nil {
		t.Fatalf("NewPrivateKeyFromBytes() error = %v", err)
	}
	sk, ok := privKey.(*secpPrivKey)
	if !ok {
		t.Fatalf("Expected *secpPrivKey, got %T", privKey)
	}
	if hex.EncodeToString(sk.Serialize()) != privKeyHex {
		t.Errorf("D value mismatch, got %s, want %s", hex.EncodeToString(sk.Serialize()), privKeyHex)
	}
}

// TestSecp256k1Algorithm_NewPrivateKeyFromBytes_InvalidLength 测试无效长度
func TestSecp256k1Algorithm_NewPrivateKeyFromBytes_InvalidLength(t *testing.T) {
	algo := NewSecp256k1Algorithm()
	_, err := algo.NewPrivateKeyFromBytes([]byte{0x01, 0x02})
	if err == nil {
		t.Error("expected error for invalid length, got nil")
	}
}

// TestSecp256k1Algorithm_Sign 测试签名
func TestSecp256k1Algorithm_Sign(t *testing.T) {
	algo := NewSecp256k1Algorithm()
	// 使用与 MockPrivKey 不同的测试值避免冲突
	testPrivKey := "218f84362a3c489e21d6f8176f03dd9a1cc208b9fcfe02f9eb2e35714e28d070"
	privKeyBytes, _ := hex.DecodeString(testPrivKey)
	privKey, _ := algo.NewPrivateKeyFromBytes(privKeyBytes)
	message, _ := hex.DecodeString("25b213b6d60d41921e1610945a0ba64562c87506191fd3b897c6cc068331f901")
	signature, err := algo.Sign(privKey, message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	fmt.Printf("signature: %s", hex.EncodeToString(signature))

	// 原始签名: R(32) || S(32) || V(1) = 65 字节
	if len(signature) != 65 {
		t.Errorf("Sign() returned %d bytes, want 65", len(signature))
	}
	if len(signature) == 0 {
		t.Fatal("Sign() returned empty signature")
	}

	// V 值表示 R.y 奇偶性: 0=偶数, 1=奇数
	v := signature[64]
	if v > 1 {
		t.Errorf("V = %d, want 0 or 1", v)
	}
}

// TestSecp256k1Algorithm_SerializePrivateKey 测试私钥序列化
func TestSecp256k1Algorithm_SerializePrivateKey(t *testing.T) {
	algo := NewSecp256k1Algorithm()
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
	// 反解析验证 DER 有效
	_, err = parsePKCS8Secp256k1(derBytes)
	if err != nil {
		t.Fatalf("SerializePrivateKey roundtrip failed: %v", err)
	}
}

// TestSecp256k1Algorithm_SerializePublicKey 测试公钥序列化
func TestSecp256k1Algorithm_SerializePublicKey(t *testing.T) {
	algo := NewSecp256k1Algorithm()
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
	// 验证 SPKI DER 结构有效
	_, err = parsePKIXSecp256k1(pubBytes)
	if err != nil {
		t.Fatalf("SerializePublicKey DER invalid: %v", err)
	}
}

// TestSecp256k1Algorithm_ParsePrivateKey 测试私钥解析
func TestSecp256k1Algorithm_ParsePrivateKey(t *testing.T) {
	algo := NewSecp256k1Algorithm()
	privKey, _, err := algo.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	derBytes, err := algo.SerializePrivateKey(privKey)
	if err != nil {
		t.Fatalf("SerializePrivateKey() error = %v", err)
	}
	parsedKey, err := algo.ParsePrivateKey(derBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKey() error = %v", err)
	}
	origSK := privKey.(*secpPrivKey)
	parsedSK := parsedKey.(*secpPrivKey)
	if !origSK.PubKey().IsEqual(parsedSK.PubKey()) {
		t.Error("Parsed key does not match original")
	}
}

// TestSecp256k1Algorithm_ClearPrivateKey 测试私钥清零
func TestSecp256k1Algorithm_ClearPrivateKey(t *testing.T) {
	algo := NewSecp256k1Algorithm()
	privKey, _, err := algo.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	sk := privKey.(*secpPrivKey)
	algo.ClearPrivateKey(privKey)
	// 清零后 D 的字节全为 0
	if hex.EncodeToString(sk.Serialize()) != "0000000000000000000000000000000000000000000000000000000000000000" {
		t.Error("ClearPrivateKey() did not zero D value")
	}
}

// TestSecp256k1Algorithm_HashFunc 测试哈希函数
func TestSecp256k1Algorithm_HashFunc(t *testing.T) {
	algo := NewSecp256k1Algorithm()
	if got := algo.HashFunc(); got != crypto.SHA256 {
		t.Errorf("HashFunc() = %v, want %v", got, crypto.SHA256)
	}
}

// TestSecp256k1Algorithm_VerifySignature 测试签名验证
func TestSecp256k1Algorithm_VerifySignature(t *testing.T) {
	algo := NewSecp256k1Algorithm()
	privKey, pubKey, err := algo.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	message := []byte("Test message for verification")
	signature, err := algo.Sign(privKey, message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// 从原始 R || S 构造 DER 用于验证
	rBytes := signature[0:32]
	sBytes := signature[32:64]
	btcPub := pubKey.(*btcec.PublicKey)
	derSig := constructDER(rBytes, sBytes)
	parsedSig, err := btcecdsa.ParseDERSignature(derSig)
	if err != nil {
		t.Fatalf("Failed to parse DER signature: %v", err)
	}
	// 注意: Sign 和 Verify 都期望原始 message，不做额外哈希
	if !parsedSig.Verify(message, btcPub) {
		t.Error("Signature verification failed")
	}
}

// TestSecp256k1Algorithm_Determinism 测试签名的确定性
func TestSecp256k1Algorithm_Determinism(t *testing.T) {
	algo := NewSecp256k1Algorithm()
	privKeyBytes, _ := hex.DecodeString(MockPrivKey1)
	privKey, _ := algo.NewPrivateKeyFromBytes(privKeyBytes)
	message, _ := hex.DecodeString("e2c1e0526103d300a350fa2031d2fc70479e11fa23aa1790c1554a0cc7924bfe")
	sig1, _ := algo.Sign(privKey, message)
	sig2, _ := algo.Sign(privKey, message)
	if hex.EncodeToString(sig1) != hex.EncodeToString(sig2) {
		t.Error("Sign() is not deterministic")
	}
}

// TestSecp256k1Algorithm_Roundtrip 测试完整序列化/反序列化循环
func TestSecp256k1Algorithm_Roundtrip(t *testing.T) {
	algo := NewSecp256k1Algorithm()
	privKey, pubKey, err := algo.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}

	privDER, _ := algo.SerializePrivateKey(privKey)
	pubDER, _ := algo.SerializePublicKey(pubKey)

	parsedPriv, err := algo.ParsePrivateKey(privDER)
	if err != nil {
		t.Fatalf("ParsePrivateKey() error = %v", err)
	}

	sk1 := privKey.(*secpPrivKey)
	sk2 := parsedPriv.(*secpPrivKey)
	if !sk1.PubKey().IsEqual(sk2.PubKey()) {
		t.Error("Private key roundtrip failed: public key mismatch")
	}
	_ = pubDER
}

// parsePKIXSecp256k1 解析 PKIX SubjectPublicKeyInfo DER，验证结构有效
func parsePKIXSecp256k1(der []byte) ([]byte, error) {
	var spki subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, err
	}
	return spki.PublicKey.Bytes, nil
}

// constructDER 将原始 R || S 字节构造为 DER 编码签名
// DER 整数是有符号的，如果 R 或 S 的最高位为 1，需要添加前导 0x00
func constructDER(r, s []byte) []byte {
	// R: 追加前导零如果需要
	var rEncoded []byte
	if len(r) > 0 && r[0]&0x80 != 0 {
		rEncoded = append([]byte{0x00}, r...)
	} else {
		rEncoded = r
	}
	// S: 追加前导零如果需要
	var sEncoded []byte
	if len(s) > 0 && s[0]&0x80 != 0 {
		sEncoded = append([]byte{0x00}, s...)
	} else {
		sEncoded = s
	}

	rLen := len(rEncoded)
	sLen := len(sEncoded)
	// DER: 0x30 <totalLen> 0x02 <rLen> <R> 0x02 <sLen> <S>
	totalContent := 4 + rLen + sLen
	result := make([]byte, 2+totalContent)
	result[0] = 0x30
	result[1] = byte(totalContent)
	result[2] = 0x02
	result[3] = byte(rLen)
	copy(result[4:4+rLen], rEncoded)
	pos := 4 + rLen
	result[pos] = 0x02
	result[pos+1] = byte(sLen)
	copy(result[pos+2:pos+2+sLen], sEncoded)
	return result
}

// TestSecp256k1Algorithm_NewPrivateKeyFromBytes_Invalid 测试无效私钥
func TestSecp256k1Algorithm_NewPrivateKeyFromBytes_Invalid(t *testing.T) {
	algo := NewSecp256k1Algorithm()

	// 零私钥
	zeroBytes := make([]byte, 32)
	_, err := algo.NewPrivateKeyFromBytes(zeroBytes)
	if err == nil {
		t.Error("expected error for zero private key, got nil")
	}

	// N (曲线阶，等于 N 是无效的)
	N := "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
	nBytes, _ := hex.DecodeString(N)
	_, err = algo.NewPrivateKeyFromBytes(nBytes)
	if err == nil {
		t.Error("expected error for D >= N, got nil")
	}

	// 长度非 32 字节
	_, err = algo.NewPrivateKeyFromBytes([]byte{0x01})
	if err == nil {
		t.Error("expected error for wrong length, got nil")
	}
}

// TestSecp256k1Algorithm_Sign_OutputFormat 测试签名输出格式
func TestSecp256k1Algorithm_Sign_OutputFormat(t *testing.T) {
	algo := NewSecp256k1Algorithm()
	privKey, _, err := algo.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	message := []byte("test message")
	sig, err := algo.Sign(privKey, message)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// 固定长度 65 字节
	if len(sig) != 65 {
		t.Errorf("signature length = %d, want 65", len(sig))
	}

	// 不以 0x30 (DER SEQUENCE) 开头
	if len(sig) > 0 && sig[0] == 0x30 {
		t.Error("signature should not be DER encoded")
	}

	// R 和 S 都不是 DER INTEGER tag (0x02)
	r := sig[0:32]
	s := sig[32:64]
	if r[0] == 0x02 || s[0] == 0x02 {
		t.Error("signature should be raw R || S, not DER")
	}

	// V 为 0 或 1，表示 R.y 的奇偶性
	v := sig[64]
	if v > 1 {
		t.Errorf("V = %d, want 0 or 1", v)
	}

	// R 和 S 都小于 secp256k1 N
	N, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	rInt := new(big.Int).SetBytes(r)
	sInt := new(big.Int).SetBytes(s)
	if rInt.Cmp(big.NewInt(0)) == 0 || rInt.Cmp(N) >= 0 {
		t.Error("R value out of range")
	}
	if sInt.Cmp(big.NewInt(0)) == 0 || sInt.Cmp(N) >= 0 {
		t.Error("S value out of range")
	}
}
