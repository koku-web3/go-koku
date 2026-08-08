package grpc

import (
	"testing"
)

// TestValidateCreateMasterKeyRequest 测试 CreateMasterKey 请求参数校验
func TestValidateCreateMasterKeyRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *CreateMasterKeyRequest
		wantErr bool
	}{
		{
			name: "valid request with ecdsa-secp256k1",
			req: &CreateMasterKeyRequest{
				TraceId:   "trace-123",
				ChainCode: "ethereum",
				KeyType:   "ecdsa-secp256k1",
			},
			wantErr: false,
		},
		{
			name: "valid request with ecdsa-secp256r1",
			req: &CreateMasterKeyRequest{
				TraceId:   "trace-123",
				ChainCode: "bitcoin",
				KeyType:   "ecdsa-secp256r1",
			},
			wantErr: false,
		},
		{
			name: "valid request with eddsa-ed25519",
			req: &CreateMasterKeyRequest{
				TraceId:   "trace-123",
				ChainCode: "solana",
				KeyType:   "eddsa-ed25519",
			},
			wantErr: false,
		},
		{
			name: "missing trace_id",
			req: &CreateMasterKeyRequest{
				TraceId:   "",
				ChainCode: "ethereum",
				KeyType:   "ecdsa-secp256k1",
			},
			wantErr: true,
		},
		{
			name: "chain_code too long",
			req: &CreateMasterKeyRequest{
				TraceId:   "trace-123",
				ChainCode: "this-is-a-very-long-chain-code-that-exceeds-36-chars",
				KeyType:   "ecdsa-secp256k1",
			},
			wantErr: true,
		},
		{
			name: "missing chain_code",
			req: &CreateMasterKeyRequest{
				TraceId:   "trace-123",
				ChainCode: "",
				KeyType:   "ecdsa-secp256k1",
			},
			wantErr: true,
		},
		{
			name: "missing key_type",
			req: &CreateMasterKeyRequest{
				TraceId:   "trace-123",
				ChainCode: "ethereum",
				KeyType:   "",
			},
			wantErr: true,
		},
		{
			name: "key_type too long",
			req: &CreateMasterKeyRequest{
				TraceId:   "trace-123",
				ChainCode: "ethereum",
				KeyType:   "this-is-a-very-long-key-type-that-exceeds-36-chars",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCreateMasterKeyRequest(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCreateMasterKeyRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestMapAlgorithmToTransitKeyType 测试算法类型映射
func TestMapAlgorithmToTransitKeyType(t *testing.T) {
	tests := []struct {
		keyType  string
		expected string
	}{
		{"ecdsa-secp256k1", "ecdsa-p256"},
		{"ecdsa-secp256r1", "ecdsa-p256"},
		{"eddsa-ed25519", "ed25519"},
		{"unknown", "aes256-gcm96"},
		{"", "aes256-gcm96"},
	}

	for _, tt := range tests {
		t.Run(tt.keyType, func(t *testing.T) {
			result := mapAlgorithmToTransitKeyType(tt.keyType)
			if result != tt.expected {
				t.Errorf("mapAlgorithmToTransitKeyType(%s) = %s, want %s", tt.keyType, result, tt.expected)
			}
		})
	}
}

// TestValidateCreateKeyRequest 测试 CreateKey 请求参数校验
func TestValidateCreateKeyRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *CreateKeyRequest
		wantErr bool
	}{
		{
			name: "valid request with ecdsa-secp256k1",
			req: &CreateKeyRequest{
				TraceId:       "trace-123",
				ChainCode:     "ethereum",
				MasterKeyName: "master-key-1",
				KeyContext:    "context-1",
				KeyType:       "ecdsa-secp256k1",
			},
			wantErr: false,
		},
		{
			name: "valid request with ecdsa-secp256r1",
			req: &CreateKeyRequest{
				TraceId:       "trace-123",
				ChainCode:     "bitcoin",
				MasterKeyName: "master-key-2",
				KeyContext:    "context-2",
				KeyType:       "ecdsa-secp256r1",
			},
			wantErr: false,
		},
		{
			name: "valid request with eddsa-ed25519",
			req: &CreateKeyRequest{
				TraceId:       "trace-123",
				ChainCode:     "solana",
				MasterKeyName: "master-key-3",
				KeyContext:    "context-3",
				KeyType:       "eddsa-ed25519",
			},
			wantErr: false,
		},
		{
			name: "missing trace_id",
			req: &CreateKeyRequest{
				TraceId:       "",
				ChainCode:     "ethereum",
				MasterKeyName: "master-key-1",
				KeyContext:    "context-1",
				KeyType:       "ecdsa-secp256k1",
			},
			wantErr: true,
		},
		{
			name: "chain_code too long",
			req: &CreateKeyRequest{
				TraceId:       "trace-123",
				ChainCode:     "this-is-a-very-long-chain-code-that-exceeds-36-chars",
				MasterKeyName: "master-key-1",
				KeyContext:    "context-1",
				KeyType:       "ecdsa-secp256k1",
			},
			wantErr: true,
		},
		{
			name: "missing chain_code",
			req: &CreateKeyRequest{
				TraceId:       "trace-123",
				ChainCode:     "",
				MasterKeyName: "master-key-1",
				KeyContext:    "context-1",
				KeyType:       "ecdsa-secp256k1",
			},
			wantErr: true,
		},
		{
			name: "unsupported key_type",
			req: &CreateKeyRequest{
				TraceId:       "trace-123",
				ChainCode:     "ethereum",
				MasterKeyName: "master-key-1",
				KeyContext:    "context-1",
				KeyType:       "rsa-2048",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCreateKeyRequest(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCreateKeyRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestValidateSignRequest 测试 Sign 请求参数校验
func TestValidateSignRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *SignRequest
		wantErr bool
	}{
		{
			name: "valid request",
			req: &SignRequest{
				TraceId:           "trace-123",
				ChainCode:         "ethereum",
				MasterKeyName:     "master-key-1",
				KeyContext:        "context-1",
				KeyType:           "ecdsa-secp256k1",
				Message:           "Hello, World!",
				PrivKeyCiphertext: "vault ciphertext",
			},
			wantErr: false,
		},
		{
			name: "missing trace_id",
			req: &SignRequest{
				TraceId:           "",
				ChainCode:         "ethereum",
				MasterKeyName:     "master-key-1",
				KeyContext:        "context-1",
				KeyType:           "ecdsa-secp256k1",
				Message:           "Hello, World!",
				PrivKeyCiphertext: "vault ciphertext",
			},
			wantErr: true,
		},
		{
			name: "message too long",
			req: &SignRequest{
				TraceId:           "trace-123",
				ChainCode:         "ethereum",
				MasterKeyName:     "master-key-1",
				KeyContext:        "context-1",
				KeyType:           "ecdsa-secp256k1",
				Message:           string(make([]byte, 1025)),
				PrivKeyCiphertext: "vault ciphertext",
			},
			wantErr: true,
		},
		{
			name: "empty message",
			req: &SignRequest{
				TraceId:           "trace-123",
				ChainCode:         "ethereum",
				MasterKeyName:     "master-key-1",
				KeyContext:        "context-1",
				KeyType:           "ecdsa-secp256k1",
				Message:           "",
				PrivKeyCiphertext: "vault ciphertext",
			},
			wantErr: true,
		},
		{
			name: "missing priv_key_ciphertext",
			req: &SignRequest{
				TraceId:           "trace-123",
				ChainCode:         "ethereum",
				MasterKeyName:     "master-key-1",
				KeyContext:        "context-1",
				KeyType:           "ecdsa-secp256k1",
				Message:           "Hello, World!",
				PrivKeyCiphertext: "",
			},
			wantErr: true,
		},
		{
			name: "unsupported key_type",
			req: &SignRequest{
				TraceId:           "trace-123",
				ChainCode:         "ethereum",
				MasterKeyName:     "master-key-1",
				KeyContext:        "context-1",
				KeyType:           "rsa-2048",
				Message:           "Hello, World!",
				PrivKeyCiphertext: "vault ciphertext",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSignRequest(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSignRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
