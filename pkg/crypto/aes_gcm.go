package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// NonceSize GCM nonce(IV) 字节长度
const NonceSize = 12

// Encrypt 使用 AES-256-GCM 加密数据
// plaintext: 待加密数据, key: 32字节 AES-256 密钥
// 返回: nonce (12字节) + ciphertext, 错误
func Encrypt(plaintext, key []byte) (nonce, ciphertext []byte, err error) {
	if len(key) != 32 {
		return nil, nil, fmt.Errorf("invalid key length: expected 32, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce = make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

// Decrypt 使用 AES-256-GCM 解密数据
// ciphertext: 密文, nonce: 12字节随机数, key: 32字节 AES-256 密钥
// 返回: 明文, 错误
func Decrypt(ciphertext, nonce, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: expected 32, got %d", len(key))
	}

	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("invalid nonce length: expected %d, got %d", NonceSize, len(nonce))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// GenerateNonce 生成12字节随机nonce
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return nonce, nil
}

// EncryptWithFixedNonce 使用提供的nonce进行AES-256-GCM加密（确定性加密）
func EncryptWithFixedNonce(plaintext, nonce, key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: expected 32, got %d", len(key))
	}

	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("invalid nonce length: expected %d, got %d", NonceSize, len(nonce))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	return gcm.Seal(nil, nonce, plaintext, nil), nil
}
