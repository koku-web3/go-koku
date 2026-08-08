package grpc

import (
	"testing"

	"github.com/koku-web3/go-koku/internal/coordinator/config"
)

func TestHexDecode(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []byte
		wantErr bool
	}{
		{
			name:    "empty string",
			input:   "",
			want:    []byte{},
			wantErr: false,
		},
		{
			name:    "simple hex",
			input:   "48656c6c6f",
			want:    []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f},
			wantErr: false,
		},
		{
			name:    "with 0x prefix",
			input:   "0x48656c6c6f",
			want:    []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f},
			wantErr: false,
		},
		{
			name:    "odd length",
			input:   "123",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid character",
			input:   "48656c6c6x",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "uppercase hex",
			input:   "0xDEADBEEF",
			want:    []byte{0xde, 0xad, 0xbe, 0xef},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hexDecode(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("hexDecode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && string(got) != string(tt.want) {
				t.Errorf("hexDecode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHexEncode(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "empty",
			input: []byte{},
			want:  "0x",
		},
		{
			name:  "hello",
			input: []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f},
			want:  "0x48656c6c6f",
		},
		{
			name:  "deadbeef",
			input: []byte{0xde, 0xad, 0xbe, 0xef},
			want:  "0xdeadbeef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hexEncode(tt.input)
			if got != tt.want {
				t.Errorf("hexEncode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSignatureToHex(t *testing.T) {
	tests := []struct {
		name      string
		signature string
		want      string
	}{
		{
			name:      "empty signature",
			signature: "",
			want:      "",
		},
		{
			name:      "short signature",
			signature: "vault:v1",
			want:      "vault:v1",
		},
		{
			name:      "invalid vault format",
			signature: "invalid",
			want:      "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := signatureToHex(tt.signature)
			if got != tt.want {
				t.Errorf("signatureToHex() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServerValidation(t *testing.T) {
	cfg := &config.GRPCConfig{
		Enable: true,
		Host:   "127.0.0.1",
		Port:   50051,
	}

	server := NewServer(nil, cfg)
	if server == nil {
		t.Error("NewServer returned nil")
		return
	}

	if server.host != "127.0.0.1" || server.port != 50051 {
		t.Errorf("Unexpected server config: host=%s, port=%d", server.host, server.port)
	}
}

func TestClientValidation(t *testing.T) {
	_, err := NewClient("")
	if err == nil {
		t.Error("NewClient should return error for invalid address")
	}
}
