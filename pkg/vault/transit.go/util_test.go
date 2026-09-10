package transit

import (
	"testing"
)

func TestGetKeyNameForCore(t *testing.T) {
	tests := []struct {
		name      string
		chainCode string
		want      string
	}{
		{
			name:      "BTC chain",
			chainCode: "BTC",
			want:      "BTC-masterkey",
		},
		{
			name:      "ETH chain",
			chainCode: "ETH",
			want:      "ETH-masterkey",
		},
		{
			name:      "empty chain code",
			chainCode: "",
			want:      "-masterkey",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetKeyNameForCore(tt.chainCode)
			if got != tt.want {
				t.Errorf("GetKeyNameForCore(%q) = %q, want %q", tt.chainCode, got, tt.want)
			}
		})
	}
}

func TestGetKeyNameForOperations(t *testing.T) {
	tests := []struct {
		name      string
		chainCode string
		want      string
	}{
		{
			name:      "BTC chain",
			chainCode: "BTC",
			want:      "BTC-privkey",
		},
		{
			name:      "ETH chain",
			chainCode: "ETH",
			want:      "ETH-privkey",
		},
		{
			name:      "empty chain code",
			chainCode: "",
			want:      "-privkey",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetKeyNameForOperations(tt.chainCode)
			if got != tt.want {
				t.Errorf("GetKeyNameForOperations(%q) = %q, want %q", tt.chainCode, got, tt.want)
			}
		})
	}
}

func TestGetKeyNameForUser(t *testing.T) {
	tests := []struct {
		name      string
		chainCode string
		want      string
	}{
		{
			name:      "BTC chain",
			chainCode: "BTC",
			want:      "BTC-privkey",
		},
		{
			name:      "ETH chain",
			chainCode: "ETH",
			want:      "ETH-privkey",
		},
		{
			name:      "empty chain code",
			chainCode: "",
			want:      "-privkey",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetKeyNameForUser(tt.chainCode)
			if got != tt.want {
				t.Errorf("GetKeyNameForUser(%q) = %q, want %q", tt.chainCode, got, tt.want)
			}
		})
	}
}

func TestBip44PathToContext(t *testing.T) {
	tests := []struct {
		name      string
		bip44Path string
		want      string
	}{
		{
			name:      "standard BIP44 path",
			bip44Path: "m/44'/60'/0'/0/0",
			want:      "m-44-60-0-0-0",
		},
		{
			name:      "BIP44 path without hardening",
			bip44Path: "m/44/60/0/0/0",
			want:      "m-44-60-0-0-0",
		},
		{
			name:      "BIP44 path with only hardenings",
			bip44Path: "m/44'/60'/0'",
			want:      "m-44-60-0",
		},
		{
			name:      "empty path",
			bip44Path: "",
			want:      "",
		},
		{
			name:      "path with multiple hardenings",
			bip44Path: "m/44'/0'/0'/0/1",
			want:      "m-44-0-0-0-1",
		},
		{
			name:      "single element path",
			bip44Path: "m/44'",
			want:      "m-44",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Bip44PathToContext(tt.bip44Path)
			if got != tt.want {
				t.Errorf("Bip44PathToContext(%q) = %q, want %q", tt.bip44Path, got, tt.want)
			}
		})
	}
}

func TestConstants(t *testing.T) {
	// Test CoreTransit constant
	if CoreTransit != "core" {
		t.Errorf("CoreTransit = %q, want %q", CoreTransit, "core")
	}

	// Test OperationsTransit constant
	if OperationsTransit != "operations" {
		t.Errorf("OperationsTransit = %q, want %q", OperationsTransit, "operations")
	}

	// Test UserTransit constant
	if UserTransit != "user" {
		t.Errorf("UserTransit = %q, want %q", UserTransit, "user")
	}

	// Test MasterKeySeedKeyName template
	expectedMasterKey := "%s-masterkey"
	if MasterKeySeedKeyName != expectedMasterKey {
		t.Errorf("MasterKeySeedKeyName = %q, want %q", MasterKeySeedKeyName, expectedMasterKey)
	}

	// Test OperationsKeyName template
	expectedOpsKey := "%s-privkey"
	if OperationsKeyName != expectedOpsKey {
		t.Errorf("OperationsKeyName = %q, want %q", OperationsKeyName, expectedOpsKey)
	}

	// Test UserKeyName template
	expectedUserKey := "%s-privkey"
	if UserKeyName != expectedUserKey {
		t.Errorf("UserKeyName = %q, want %q", UserKeyName, expectedUserKey)
	}
}
