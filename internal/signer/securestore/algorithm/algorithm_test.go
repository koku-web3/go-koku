package algorithm

import (
	"crypto"
	"testing"
)

// mockAlgorithm 用于测试的模拟算法
type mockAlgorithm struct {
	id string
}

func (m *mockAlgorithm) AlgorithmID() string { return m.id }

func (m *mockAlgorithm) GenerateKey() (crypto.PrivateKey, crypto.PublicKey, error) {
	return nil, nil, nil
}

func (m *mockAlgorithm) Sign(_ crypto.PrivateKey, _ []byte) ([]byte, error) {
	return nil, nil
}

func (m *mockAlgorithm) SerializePrivateKey(_ crypto.PrivateKey) ([]byte, error) {
	return nil, nil
}

func (m *mockAlgorithm) SerializePublicKey(_ crypto.PublicKey) ([]byte, error) {
	return nil, nil
}

func (m *mockAlgorithm) ParsePrivateKey(_ []byte) (crypto.PrivateKey, error) {
	return nil, nil
}

func (m *mockAlgorithm) ClearPrivateKey(_ crypto.PrivateKey) {}

func (m *mockAlgorithm) HashFunc() crypto.Hash { return crypto.Hash(0) }

// TestRegister 测试算法注册
func TestRegister(t *testing.T) {
	algo := &mockAlgorithm{id: "test-mock"}

	err := Register(algo)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	// 验证已注册
	got, err := Get("test-mock")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if got.AlgorithmID() != "test-mock" {
		t.Errorf("Get() = %v, want %v", got.AlgorithmID(), "test-mock")
	}
}

// TestRegister_NilAlgorithm 测试注册 nil 算法
func TestRegister_NilAlgorithm(t *testing.T) {
	err := Register(nil)
	if err == nil {
		t.Error("Register(nil) should return error")
	}
}

// TestRegister_EmptyID 测试注册空 ID 算法
func TestRegister_EmptyID(t *testing.T) {
	algo := &mockAlgorithm{id: ""}
	err := Register(algo)
	if err == nil {
		t.Error("Register(empty id) should return error")
	}
}

// TestGet_NotFound 测试获取不存在的算法
func TestGet_NotFound(t *testing.T) {
	_, err := Get("non-existent")
	if err == nil {
		t.Error("Get(non-existent) should return error")
	}
}

// TestGetAll 测试获取所有算法
func TestGetAll(t *testing.T) {
	algos := GetAll()

	if len(algos) == 0 {
		t.Error("GetAll() returned empty map")
	}

	// 验证已知算法存在
	expectedAlgos := []string{"ecdsa-secp256k1", "ecdsa-secp256r1", "eddsa-ed25519"}
	for _, id := range expectedAlgos {
		if _, ok := algos[id]; !ok {
			t.Errorf("Expected algorithm %s not found", id)
		}
	}
}

// TestIsSupported 测试算法支持检查
func TestIsSupported(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want bool
	}{
		{"supported ecdsa-secp256r1", "ecdsa-secp256r1", true},
		{"supported ecdsa-secp256k1", "ecdsa-secp256k1", true},
		{"supported eddsa-ed25519", "eddsa-ed25519", true},
		{"unsupported", "unsupported-algo", false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSupported(tt.id); got != tt.want {
				t.Errorf("IsSupported(%s) = %v, want %v", tt.id, got, tt.want)
			}
		})
	}
}

// TestRegister_Override 测试覆盖已有算法
func TestRegister_Override(t *testing.T) {
	algo1 := &mockAlgorithm{id: "override-test"}
	algo2 := &mockAlgorithm{id: "override-test"}

	if err := Register(algo1); err != nil {
		t.Fatalf("Register(algo1) error = %v", err)
	}
	if err := Register(algo2); err != nil {
		t.Fatalf("Register(algo2) error = %v", err)
	}

	got, _ := Get("override-test")
	// 应该能获取到第二个算法（虽然内容相同）
	if got.AlgorithmID() != "override-test" {
		t.Errorf("Get() = %v, want %v", got.AlgorithmID(), "override-test")
	}
}

// TestConcurrentAccess 测试并发访问
func TestConcurrentAccess(t *testing.T) {
	// 这个测试主要验证并发访问不会 panic
	done := make(chan bool)

	for i := 0; i < 100; i++ {
		go func() {
			_ = GetAll()
			_ = IsSupported("ecdsa-secp256r1")
			_, _ = Get("eddsa-ed25519")
			done <- true
		}()
	}

	for i := 0; i < 100; i++ {
		<-done
	}
}

// TestDefaultAlgorithms 测试默认注册的算法
func TestDefaultAlgorithms(t *testing.T) {
	algos := []struct {
		id       string
		generate bool
		sign     bool
	}{
		{"ecdsa-secp256r1", true, true},
		{"ecdsa-secp256k1", true, true},
		{"eddsa-ed25519", true, true},
	}

	for _, algo := range algos {
		t.Run(algo.id, func(t *testing.T) {
			a, err := Get(algo.id)
			if err != nil {
				t.Fatalf("Get(%s) error = %v", algo.id, err)
			}

			if a.AlgorithmID() != algo.id {
				t.Errorf("AlgorithmID() = %v, want %v", a.AlgorithmID(), algo.id)
			}

			if algo.generate {
				_, _, err := a.GenerateKey()
				if err != nil {
					t.Errorf("GenerateKey() error = %v", err)
				}
			}
		})
	}
}
