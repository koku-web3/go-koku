package securestore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/tyler-smith/go-bip32"
)

// buildPEMPrivateKey 通过算法生成一对密钥并返回 PKCS#8 DER + PEM(base64) 形式
func buildPEMPrivateKey(t *testing.T, algoID string) (cryptoKey interface{}, der []byte, pemB64 string) {
	t.Helper()

	switch algoID {
	case "ecdsa-secp256r1":
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey error = %v", err)
		}
		derBytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatalf("MarshalPKCS8 error = %v", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: derBytes})
		return priv, derBytes, base64.StdEncoding.EncodeToString(pemBytes)
	case "eddsa-ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519.GenerateKey error = %v", err)
		}
		_ = pub
		derBytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatalf("MarshalPKCS8 error = %v", err)
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: derBytes})
		return priv, derBytes, base64.StdEncoding.EncodeToString(pemBytes)
	default:
		t.Fatalf("unsupported test algo: %s", algoID)
		return
	}
}

// TestNewSecurePrivateKey 验证密钥包装器正确持有私钥引用并复制原始 DER
func TestNewSecurePrivateKey(t *testing.T) {
	algoID := "ecdsa-secp256r1"
	priv, der, _ := buildPEMPrivateKey(t, algoID)

	spk := NewSecurePrivateKey(priv, der, algoID)
	if spk == nil {
		t.Fatal("NewSecurePrivateKey returned nil")
	}
	if spk.IsCleared() {
		t.Error("new SecurePrivateKey must not be cleared")
	}
	if spk.Key() != priv {
		t.Error("Key() should return the original private key handle")
	}

	// 修改原始 der 不应影响副本
	der[0] ^= 0xFF
	if spk.keyBytes[0] == der[0] {
		t.Error("keyBytes must be an independent copy of the input DER")
	}
}

// TestSecurePrivateKey_Clear_ECDSA 验证 ECDSA 私钥 Clear 后 D 被置零、IsCleared 为 true、二次 Clear 安全
func TestSecurePrivateKey_Clear_ECDSA(t *testing.T) {
	algoID := "ecdsa-secp256r1"
	priv, der, _ := buildPEMPrivateKey(t, algoID)
	ecdsaKey := priv.(*ecdsa.PrivateKey)

	spk := NewSecurePrivateKey(priv, der, algoID)
	spk.Clear()

	if !spk.IsCleared() {
		t.Error("IsCleared() should be true after Clear()")
	}
	if spk.Key() != nil {
		t.Error("Key() should be nil after Clear()")
	}
	if ecdsaKey.D == nil || ecdsaKey.D.Sign() != 0 {
		t.Error("ECDSA private key D should be zero after Clear()")
	}

	// 二次 Clear 不应 panic
	spk.Clear()
	if !spk.IsCleared() {
		t.Error("IsCleared() should remain true after repeated Clear")
	}
}

// TestSecurePrivateKey_Clear_Ed25519 验证 Ed25519 私钥 Clear 后底层字节被清零
func TestSecurePrivateKey_Clear_Ed25519(t *testing.T) {
	algoID := "eddsa-ed25519"
	priv, der, _ := buildPEMPrivateKey(t, algoID)
	edKey, ok := priv.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("expected ed25519.PrivateKey, got %T", priv)
	}

	spk := NewSecurePrivateKey(priv, der, algoID)

	// 记录 Clear 前的副本以对比
	before := append([]byte(nil), []byte(edKey)...)

	spk.Clear()
	if !spk.IsCleared() {
		t.Error("IsCleared() should be true after Clear()")
	}

	allZero := true
	for _, b := range []byte(edKey) {
		if b != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Errorf("ed25519 private key bytes should be zeroed after Clear (was %x, before snapshot %x)", []byte(edKey), before)
	}

	spk.Clear()
}

// TestMemzeroBip32Key 验证对 bip32.Key 五个敏感字段的清零行为
func TestMemzeroBip32Key(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, 64)
	master, err := bip32.NewMasterKey(seed)
	if err != nil {
		t.Fatalf("bip32.NewMasterKey error = %v", err)
	}

	// 保留字段的独立副本以确认 Clear 后这些 slice 本身被清零
	keyBefore := append([]byte(nil), master.Key...)
	chainBefore := append([]byte(nil), master.ChainCode...)
	childBefore := append([]byte(nil), master.ChildNumber...)
	fpBefore := append([]byte(nil), master.FingerPrint...)
	verBefore := append([]byte(nil), master.Version...)

	if len(keyBefore) == 0 || len(chainBefore) == 0 {
		t.Fatal("bip32 master key should have populated Key and ChainCode")
	}

	MemzeroBip32Key(master)

	for i, b := range master.Key {
		if b != 0 {
			t.Errorf("master.Key[%d] = %#x, want 0", i, b)
		}
	}
	for i, b := range master.ChainCode {
		if b != 0 {
			t.Errorf("master.ChainCode[%d] = %#x, want 0", i, b)
		}
	}
	for i, b := range master.ChildNumber {
		if b != 0 {
			t.Errorf("master.ChildNumber[%d] = %#x, want 0", i, b)
		}
	}
	for i, b := range master.FingerPrint {
		if b != 0 {
			t.Errorf("master.FingerPrint[%d] = %#x, want 0", i, b)
		}
	}
	for i, b := range master.Version {
		if b != 0 {
			t.Errorf("master.Version[%d] = %#x, want 0", i, b)
		}
	}

	// 确认原始拷贝确实非零(避免假阴性)
	// ChildNumber/FingerPrint/Version 在 master key 中是空切片,不进行此检查
	if bytes.Equal(keyBefore, master.Key) {
		t.Error("original Key should have been non-zero before Clear")
	}
	if bytes.Equal(chainBefore, master.ChainCode) {
		t.Error("original ChainCode should have been non-zero before Clear")
	}
	_ = childBefore
	_ = fpBefore
	_ = verBefore
}

// TestMemzeroBip32Key_NilSafe 验证 nil 与重复调用安全
func TestMemzeroBip32Key_NilSafe(t *testing.T) {
	// nil 必须安全
	MemzeroBip32Key(nil)

	// 构造一个 key,清零后字段都为 0
	seed := bytes.Repeat([]byte{0x11}, 64)
	master, err := bip32.NewMasterKey(seed)
	if err != nil {
		t.Fatalf("bip32.NewMasterKey error = %v", err)
	}

	MemzeroBip32Key(master)
	// 二次调用不应 panic
	MemzeroBip32Key(master)
}
