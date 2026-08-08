package chain

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestHexDecode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []byte
		hasError bool
	}{
		{
			name:     "simple hex string",
			input:    "48656c6c6f576f726c64",
			expected: []byte("HelloWorld"),
		},
		{
			name:     "hex string with 0x prefix",
			input:    "0x48656c6c6f576f726c64",
			expected: []byte("HelloWorld"),
		},
		{
			name:     "single byte",
			input:    "ff",
			expected: []byte{0xff},
		},
		{
			name:     "empty string",
			input:    "",
			expected: []byte{},
		},
		{
			name:     "mixed case",
			input:    "0xDEADBEEF",
			expected: []byte{0xde, 0xad, 0xbe, 0xef},
		},
		{
			name:     "odd length should error",
			input:    "abc",
			hasError: true,
		},
		{
			name:     "invalid character should error",
			input:    "xyz",
			hasError: true,
		},
		{
			name:     "all zeros",
			input:    "0000",
			expected: []byte{0x00, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := hexDecode(tt.input)
			if tt.hasError {
				if err == nil {
					t.Errorf("hexDecode(%q) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("hexDecode(%q) unexpected error: %v", tt.input, err)
				return
			}
			if string(result) != string(tt.expected) {
				t.Errorf("hexDecode(%q) = %x, want %x", tt.input, result, tt.expected)
			}
		})
	}
}

func TestHexDecode_EdgeCases(t *testing.T) {
	result1, _ := hexDecode("abcdef")
	result2, _ := hexDecode("ABCDEF")
	if string(result1) != string(result2) {
		t.Error("hexDecode should be case insensitive")
	}

	result3, _ := hexDecode("0x")
	if len(result3) != 0 {
		t.Errorf("hexDecode(\"0x\") = %x, want empty", result3)
	}

	longHex := "0xa9059cbb000000000000000000000000d8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
	result, err := hexDecode(longHex)
	if err != nil {
		t.Errorf("hexDecode failed for long hex: %v", err)
	}
	if len(result) == 0 {
		t.Error("hexDecode should not return empty result for valid long hex")
	}
}

func TestCreateMasterKey_InvalidRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		body       string
		wantStatus int
	}{
		{
			name:       "missing chain",
			body:       `{"name": "test-key", "type": "ecdsa-p256"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing name",
			body:       `{"chain": "eth", "type": "ecdsa-p256"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing type",
			body:       `{"chain": "eth", "name": "test-key"}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid json",
			body:       `{invalid}`,
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("POST", "/api/keys", strings.NewReader(tt.body))
			c.Request.Header.Set("Content-Type", "application/json")

			service := &ChainService{vaultClient: nil}
			service.CreateMasterKey(c)

			if w.Code != tt.wantStatus {
				t.Errorf("CreateMasterKey() status = %d, want %d", w.Code, tt.wantStatus)
			}
		})
	}
}

func TestCreateMasterKey_ValidRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	body := `{"chain": "eth", "name": "test-key", "type": "ecdsa-p256", "derived": true}`

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/api/keys", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")

	var request struct {
		Chain   string `json:"chain" binding:"required"`
		Name    string `json:"name" binding:"required"`
		Type    string `json:"type" binding:"required"`
		Derived bool   `json:"derived"`
	}

	if err := json.NewDecoder(strings.NewReader(body)).Decode(&request); err != nil {
		t.Fatalf("Failed to parse request: %v", err)
	}

	if request.Chain != "eth" {
		t.Errorf("Chain = %s, want eth", request.Chain)
	}
	if request.Name != "test-key" {
		t.Errorf("Name = %s, want test-key", request.Name)
	}
	if request.Type != "ecdsa-p256" {
		t.Errorf("Type = %s, want ecdsa-p256", request.Type)
	}
	if !request.Derived {
		t.Error("Derived should be true")
	}

	gin.SetMode(gin.TestMode)
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	c2.Request = httptest.NewRequest("POST", "/api/keys", strings.NewReader(body))
	c2.Request.Header.Set("Content-Type", "application/json")

	type testRequest struct {
		Chain   string `json:"chain" binding:"required"`
		Name    string `json:"name" binding:"required"`
		Type    string `json:"type" binding:"required"`
		Derived bool   `json:"derived"`
	}
	var req testRequest
	if err := c2.ShouldBindJSON(&req); err != nil {
		t.Errorf("ShouldBindJSON failed: %v", err)
	}

	bodyNoDerived := `{"chain": "sol", "name": "wallet-key", "type": "ed25519"}`
	var reqNoDerived testRequest
	w3 := httptest.NewRecorder()
	c3, _ := gin.CreateTestContext(w3)
	c3.Request = httptest.NewRequest("POST", "/api/keys", strings.NewReader(bodyNoDerived))
	c3.Request.Header.Set("Content-Type", "application/json")
	if err := c3.ShouldBindJSON(&reqNoDerived); err != nil {
		t.Errorf("ShouldBindJSON failed for no-derived case: %v", err)
	}
	if reqNoDerived.Derived != false {
		t.Error("Derived should default to false when not provided")
	}
}

func TestSignatureToHex(t *testing.T) {
	testData := []byte{0xde, 0xad, 0xbe, 0xef}
	b64Data := base64.StdEncoding.EncodeToString(testData)
	validVaultSig := "vault:v1:" + b64Data

	tests := []struct {
		name      string
		signature string
		wantHex   string
	}{
		{
			name:      "valid vault signature",
			signature: validVaultSig,
			wantHex:   "0xdeadbeef",
		},
		{
			name:      "empty signature",
			signature: "",
			wantHex:   "",
		},
		{
			name:      "signature without prefix",
			signature: "justsomebase64data",
			wantHex:   "justsomebase64data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := signatureToHex(tt.signature)
			if result != tt.wantHex {
				t.Errorf("signatureToHex(%q) = %q, want %q", tt.signature, result, tt.wantHex)
			}
		})
	}
}

func TestHexEncode(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "simple bytes",
			input:    []byte{0xde, 0xad, 0xbe, 0xef},
			expected: "0xdeadbeef",
		},
		{
			name:     "empty bytes",
			input:    []byte{},
			expected: "0x",
		},
		{
			name:     "single byte",
			input:    []byte{0xff},
			expected: "0xff",
		},
		{
			name:     "hello world",
			input:    []byte("HelloWorld"),
			expected: "0x48656c6c6f576f726c64",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hexEncode(tt.input)
			if result != tt.expected {
				t.Errorf("hexEncode(%x) = %s, want %s", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSignatureToHex_Integration(t *testing.T) {
	testData := []byte("HelloWorld")
	b64Data := base64.StdEncoding.EncodeToString(testData)
	vaultSig := "vault:v1:" + b64Data

	hexResult := signatureToHex(vaultSig)
	expectedHex := hexEncode(testData)

	if hexResult != expectedHex {
		t.Errorf("signatureToHex(%q) = %q, want %q", vaultSig, hexResult, expectedHex)
	}
}
