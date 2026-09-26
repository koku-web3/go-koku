package kms

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/koku-web3/go-koku/internal/key-creator/config"
	log "github.com/koku-web3/go-koku/pkg/logko"
	"github.com/koku-web3/go-koku/pkg/vault"
)

type KMS struct {
	vault *vault.VaultClient
}

// DataKey 数据加密密钥结构体
type DataKey struct {
	Plaintext  string // base64 编码的 DEK 明文
	Ciphertext string // DEK 密文 (带 vault:v1: 前缀)
}

func NewKMS(ctx context.Context, vaultCfg *config.VaultConfig, awsCfg *config.AWSConfig) (*KMS, error) {
	// 1. 初始化 VaultClient
	vc, err := vault.NewVaultClient(&vault.Cfg{
		Address:              vaultCfg.Address,
		MountPath:            vaultCfg.MountPath,
		RoleName:             vaultCfg.RoleName,
		TokenRefreshInterval: vaultCfg.TokenRefreshInterval,
		CACertFile:           vaultCfg.CACertFile,
		AWS: vault.AwsCfg{
			IAMUserEnable: awsCfg.IAMUserEnable,
			AccessKey:     awsCfg.AccessKey,
			SecretKey:     awsCfg.SecretKey,
			RoleARN:       awsCfg.RoleARN,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	// 立即进行首次认证，确保服务启动时 Vault 连接正常
	if err := vc.Authenticate(); err != nil {
		return nil, fmt.Errorf("failed to authenticate with Vault: %w", err)
	}

	// 从配置获取刷新间隔（秒），转换为 time.Duration
	refreshInterval := time.Duration(vaultCfg.TokenRefreshInterval) * time.Second
	// 启动定时刷新 token 任务
	// 直到收到 context.cancel() 停止
	vc.TokenRefreshSchedule(ctx, refreshInterval)

	return &KMS{
		vault: vc,
	}, nil
}

// CreateKey 在 Vault Transit Engine 中创建密钥
// transitName: transit引擎名称 ./pkg/vault/transit/util.go
// name: 密钥名称
// keyType: 密钥类型（如 aes256-gcm96, ed25519）
// derived: 是否使用派生密钥（启用后相同输入会生成不同密钥）
func (k *KMS) CreateKey(transitName, name string, keyType string, derived bool) error {
	// Transit Engine 密钥路径格式: transit/{transitName}/keys/{key_name}
	keyPath := fmt.Sprintf("transit/%s/keys/%s", transitName, name)

	// 构造创建密钥的请求 payload
	payload := map[string]interface{}{
		"type":    keyType, // 密钥算法类型
		"derived": derived, // 是否启用派生
	}

	// 调用 Vault API 创建密钥
	secret, err := k.vault.GetClient().Logical().Write(keyPath, payload)
	if err != nil {
		return fmt.Errorf("failed to create master key for chain %s: %w", transitName, err)
	}

	// 记录创建结果
	if secret != nil {
		log.Info("Successfully created master key", "transit_name", transitName, "key_name", name)
	} else {
		log.Info("Master key already exists (nil response)", "chain", transitName)
	}

	return nil
}

// ListKeys 列出指定链的所有密钥
// transitName: transit引擎名称 ./pkg/vault/transit/util.go
// 返回: 包含密钥列表的 Secret 对象
func (k *KMS) ListKeys(transitName string) (*api.Secret, error) {
	// Transit Engine 密钥列表路径: transit/{transitName}/keys (使用 LIST 方法)
	keyPath := fmt.Sprintf("transit/%s/keys", transitName)
	return k.vault.GetClient().Logical().List(keyPath)
}

// ReadKey 读取指定密钥的详细信息
// transitName: transit引擎名称 ./pkg/vault/transit/util.go
// keyName: 密钥名称
// 返回: 包含密钥信息的 Secret 对象
func (k *KMS) ReadKey(transitName, keyName string) (*api.Secret, error) {
	// Transit Engine 密钥读取路径: transit/{transitName}/keys/{key_name}
	keyPath := fmt.Sprintf("transit/%s/keys/%s", transitName, keyName)
	return k.vault.GetClient().Logical().Read(keyPath)
}

// Decrypt 使用 Vault Transit Engine 对密文进行解密
// transitName: transit引擎名称 ./pkg/vault/transit/util.go
// keyName: 密钥名称
// ciphertext: 要解密的密文（base64 格式）
// context: 解密上下文（可选，用于派生密钥）
// 返回: Base64 编码的明文字符串
//
// 示例：
//
//		curl --header "X-Vault-Token: hvs.g1bZWi6flTJdB5GZopREVdBU" \
//		     --request POST \
//		     --data '{
//	     "ciphertext": "vault:v1:53zio/jBdPnoeZHXE93HV+c+QJIDuVc7zvCA6bt4AH0vd+GietxwPbTbRDBvdQodBvEPQhCgscm3PKBQ",
//	     "context": "ZXRoZXJldW0tdGVzdC11c2VyLTE="
//		     }' \
//		     http://127.0.0.1:8200/v1/transit/masterkey/decrypt/ethereum-masterkey
//
// 从 Hashicorp Vault 系统的角度来分析
// {transit/core} 是 transit 引擎的名字
// {encrypt} 表示加密操作
// {ethereum-masterkey} 表示 密钥名称，对应 `name`
func (k *KMS) Decrypt(transitName, keyName string, ciphertext string, context string) (string, error) {
	// Transit Engine 解密路径格式: transit/{transitName}/decrypt/{key_name}
	decryptPath := fmt.Sprintf("transit/%s/decrypt/%s", transitName, keyName)

	// Vault Transit Engine 要求 ciphertext 和 context 使用 base64 格式
	// ciphertext 在存入数据库时已经是带有 vault 前缀的base64格式，所以这里直接使用即可
	payload := map[string]interface{}{
		"ciphertext": ciphertext,
	}

	// 如果提供了 context，添加到 payload 中
	if context != "" {
		payload["context"] = base64.StdEncoding.EncodeToString([]byte(context))
	}

	// 调用 Vault API 执行解密
	secret, err := k.vault.GetClient().Logical().Write(decryptPath, payload)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt data by call %s: %w", decryptPath, err)
	}

	// 验证响应
	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("empty response from Vault during decryption by call %s", decryptPath)
	}

	// 从响应中提取明文结果（base64 格式）
	plaintext, ok := secret.Data["plaintext"].(string)
	if !ok {
		return "", fmt.Errorf("invalid plaintext format in response by call %s", decryptPath)
	}

	return plaintext, nil
}

// Encrypt 使用 Vault Transit Engine 对数据进行加密
// transitName: transit引擎名称 ./pkg/vault/transit/util.go
// keyName: 密钥名称
// plaintext: 要加密的明文数据
// context: 加密上下文（可选，用于派生密钥）
// 返回: Base64 编码的密文字符串
//
// 示例：
//
//	curl --header "X-Vault-Token: hvs.g1bZWi6flTJdB5GZopREVdBU" \
//	     --request POST \
//	     --data '{
//	       "plaintext": "MTIzNDU2Nzg5MA==",
//	       "context": "ZXRoZXJldW0tdGVzdC11c2VyLTE="
//	     }' \
//	     http://127.0.0.1:8200/v1/transit/masterkey/encrypt/ethereum-masterkey
//
// 从 Hashicorp Vault 系统的角度来分析
// {transit/core} 是 transit 引擎的名字
// {encrypt} 表示加密操作
// {ethereum-masterkey} 表示 密钥名称，对应 `name`
func (k *KMS) Encrypt(transitName, keyName string, plaintext []byte, context string) (string, error) {
	// Transit Engine 加密路径格式: transit/{transitName}/encrypt/{keyName}
	encryptPath := fmt.Sprintf("transit/%s/encrypt/%s", transitName, keyName)

	// Vault Transit Engine 要求 plaintext 和 context 使用 base64 格式
	payload := map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(plaintext),
	}

	// 如果提供了 context，添加到 payload 中
	if context != "" {
		payload["context"] = base64.StdEncoding.EncodeToString([]byte(context))
	}

	log.Info("Call Vault Service", "path", encryptPath, "plaintext_length", len(plaintext), "context_length", len(context))
	// 调用 Vault API 执行加密
	secret, err := k.vault.GetClient().Logical().Write(encryptPath, payload)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt data: %w", err)
	}

	// 验证响应
	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("empty response from Vault during encryption")
	}

	// 从响应中提取密文结果（base64 格式）
	ciphertext, ok := secret.Data["ciphertext"].(string)
	if !ok {
		return "", fmt.Errorf("invalid ciphertext format in response")
	}

	return ciphertext, nil
}

// GenerateDataKey 调用 Vault Transit datakey/plaintext/{keyName} 生成 DEK
// transitName: transit引擎名称 (core/operations/user)
// keyName: 密钥名称 (如 ethereum-masterkey)
// context: 密钥派生上下文
// 返回: plaintext (base64 DEK明文), ciphertext (DEK密文, 带vault:v1:前缀)
func (k *KMS) GenerateDataKey(transitName, keyName, context string) (*DataKey, error) {
	if strings.TrimSpace(transitName) == "" {
		return nil, fmt.Errorf("transitName cannot be empty")
	}
	if strings.TrimSpace(keyName) == "" {
		return nil, fmt.Errorf("keyName cannot be empty")
	}
	if strings.TrimSpace(context) == "" {
		return nil, fmt.Errorf("context cannot be empty")
	}

	datakeyPath := fmt.Sprintf("transit/%s/datakey/plaintext/%s", transitName, keyName)

	payload := map[string]interface{}{
		"context": base64.StdEncoding.EncodeToString([]byte(context)),
	}

	log.Debug("Generate data key from Vault", "path", datakeyPath, "context_length", len(context))
	secret, err := k.vault.GetClient().Logical().Write(datakeyPath, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to generate data key: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("Vault response is empty")
	}

	plaintext, ok := secret.Data["plaintext"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid plaintext format in data key response")
	}

	ciphertext, ok := secret.Data["ciphertext"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid ciphertext format in data key response")
	}

	return &DataKey{Plaintext: plaintext, Ciphertext: ciphertext}, nil
}

// DecryptDataKey 使用 Vault Transit 解密 DEK ciphertext
// transitName: transit引擎名称
// keyName: 密钥名称
// ciphertext: GenerateDataKey返回的ciphertext
// context: 密钥派生上下文
// 返回: plaintext (base64 DEK明文)
func (k *KMS) DecryptDataKey(transitName, keyName, ciphertext, context string) (string, error) {
	decryptPath := fmt.Sprintf("transit/%s/decrypt/%s", transitName, keyName)

	payload := map[string]interface{}{
		"ciphertext": ciphertext,
	}

	if context != "" {
		payload["context"] = base64.StdEncoding.EncodeToString([]byte(context))
	}

	log.Debug("Decrypt data key via Vault", "path", decryptPath, "context_length", len(context))
	secret, err := k.vault.GetClient().Logical().Write(decryptPath, payload)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt data key: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("Vault response is empty")
	}

	plaintext, ok := secret.Data["plaintext"].(string)
	if !ok {
		return "", fmt.Errorf("invalid plaintext format in data key decrypt response")
	}

	return plaintext, nil
}
