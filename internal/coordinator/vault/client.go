package vault

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/koku-web3/go-koku/internal/coordinator/config"
	log "github.com/koku-web3/go-koku/pkg/logko"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/hashicorp/vault/api"
	vaultaws "github.com/hashicorp/vault/api/auth/aws"
)

// VaultClient Vault 客户端结构体
// 用于管理 Vault 连接、认证和密钥操作
type VaultClient struct {
	client     *api.Client    // Vault API 客户端实例
	cfg        *config.Config // 应用配置
	token      string         // 当前有效的 Vault Token
	tokenMutex sync.RWMutex   // 读写锁，保护 token 的并发访问
	leaseTime  time.Time      // Token 的过期时间
}

// NewVaultClient 创建新的 Vault 客户端实例
// 使用配置中的地址初始化 Vault 连接
func NewVaultClient(cfg *config.Config) (*VaultClient, error) {
	// 获取默认的 Vault 配置（包含默认的 TLS 设置等）
	vaultConfig := api.DefaultConfig()
	// 设置 Vault 服务器地址
	vaultConfig.Address = cfg.Vault.Address

	// 使用配置创建 Vault 客户端
	client, err := api.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	return &VaultClient{
		client: client,
		cfg:    cfg,
	}, nil
}

func (v *VaultClient) GetClient() *api.Client {
	return v.client
}

func (v *VaultClient) GetConfig() *config.Config {
	return v.cfg
}

// GetToken 获取当前有效的 Vault Token
// 如果缓存的 token 未过期（剩余时间 > 1 分钟），直接返回缓存的 token
// 否则重新进行认证获取新 token
func (v *VaultClient) GetToken() (string, error) {
	// 使用读锁并发读取 token 和过期时间
	v.tokenMutex.RLock()
	token := v.token
	leaseTime := v.leaseTime
	v.tokenMutex.RUnlock()

	// 检查缓存的 token 是否有效：token 不为空 且 距离过期还有超过 1 分钟
	if token != "" && time.Until(leaseTime) > time.Minute {
		return token, nil
	}

	// token 过期或不存在，需要重新认证
	if err := v.Authenticate(); err != nil {
		return "", err
	}

	// 认证成功后，使用读锁获取新 token
	v.tokenMutex.RLock()
	defer v.tokenMutex.RUnlock()
	return v.token, nil
}

// Authenticate 使用 AWS IAM Role 进行 Vault 认证
// 认证流程：创建 STS Client -> AssumeRole 获取临时凭证 -> 使用凭证登录 Vault
func (v *VaultClient) Authenticate() error {
	ctx := context.Background()

	log.Info("Starting Vault authentication with AWS IAM Role", "role_arn", v.cfg.AWS.RoleARN)

	var stsClient *sts.Client
	// 根据配置决定使用哪种 AWS 凭证来源
	if v.cfg.AWS.IAMUserEnable {
		// 使用配置文件中的 IAM User 静态凭证创建 STS Client
		log.Info("Using IAM User credentials for STS AssumeRole")
		stsClient = sts.New(sts.Options{
			Region: "us-east-1",
			// 从配置读取 AccessKey 和 SecretKey
			Credentials: credentials.NewStaticCredentialsProvider(
				v.cfg.AWS.AccessKey,
				v.cfg.AWS.SecretKey,
				"", // SessionToken 为空，因为这是长期凭证
			),
		})
	} else {
		// 使用 EC2 实例角色（通过 AWS 元数据服务获取临时凭证）
		log.Info("Using EC2 Instance Profile credentials for STS AssumeRole")
		stsClient = sts.New(sts.Options{
			Region: "us-east-1", // STS 不指定凭证，让其自动从 EC2 元数据获取
		})
	}

	log.Info("Calling STS AssumeRole", "role_arn", v.cfg.AWS.RoleARN)

	// 构造 AssumeRole 请求，使用配置的 Role ARN
	assumeRoleInput := &sts.AssumeRoleInput{
		RoleArn: aws.String(v.cfg.AWS.RoleARN),
		// SessionName 用于在 CloudTrail 中标识这次 AssumeRole 操作
		RoleSessionName: aws.String("vault-aws-auth-session"),
	}

	// 调用 STS AssumeRole 获取临时安全凭证
	assumeResult, err := stsClient.AssumeRole(ctx, assumeRoleInput)
	if err != nil {
		return fmt.Errorf("failed to assume IAM role: %w", err)
	}

	// 确保返回了凭证
	if assumeResult.Credentials == nil {
		return fmt.Errorf("no credentials returned from AssumeRole")
	}

	log.Info("STS AssumeRole succeeded, got temporary credentials", "expiration", assumeResult.Credentials.Expiration.Format("2006-01-02T15:04:05Z07:00"))

	// 将临时凭证设置为环境变量，供 Vault AWS Auth Method 使用
	// Vault SDK 会自动读取这些环境变量进行 IAM 认证
	if err := os.Setenv("AWS_ACCESS_KEY_ID", *assumeResult.Credentials.AccessKeyId); err != nil {
		return fmt.Errorf("failed to set AWS_ACCESS_KEY_ID: %w", err)
	}
	if err := os.Setenv("AWS_SECRET_ACCESS_KEY", *assumeResult.Credentials.SecretAccessKey); err != nil {
		return fmt.Errorf("failed to set AWS_SECRET_ACCESS_KEY: %w", err)
	}
	if err := os.Setenv("AWS_SESSION_TOKEN", *assumeResult.Credentials.SessionToken); err != nil {
		return fmt.Errorf("failed to set AWS_SESSION_TOKEN: %w", err)
	}

	// 函数返回前清理环境变量，防止凭证泄漏
	defer func() {
		if err := os.Unsetenv("AWS_ACCESS_KEY_ID"); err != nil {
			log.Error("failed to unset AWS_ACCESS_KEY_ID", "error", err)
		}
		if err := os.Unsetenv("AWS_SECRET_ACCESS_KEY"); err != nil {
			log.Error("failed to unset AWS_SECRET_ACCESS_KEY", "error", err)
		}
		if err := os.Unsetenv("AWS_SESSION_TOKEN"); err != nil {
			log.Error("failed to unset AWS_SESSION_TOKEN", "error", err)
		}
	}()

	log.Info("Authenticating with Vault",
		"role_name", v.cfg.Vault.RoleName,
		"mount_path", v.cfg.Vault.MountPath)

	// 创建 Vault AWS Auth 方法实例
	// WithRole 指定 Vault 中配置的 AWS Auth Role 名称
	// WithMountPath 指定 AWS Auth Method 的挂载路径（默认是 aws）
	auth, err := vaultaws.NewAWSAuth(
		vaultaws.WithRole(v.cfg.Vault.RoleName),
		vaultaws.WithMountPath(v.cfg.Vault.MountPath),
	)
	if err != nil {
		return fmt.Errorf("failed to create AWS auth method: %w", err)
	}

	// 使用 Vault 客户端进行登录认证
	authInfo, err := v.client.Auth().Login(ctx, auth)
	if err != nil {
		return fmt.Errorf("failed to authenticate with Vault: %w", err)
	}

	// 验证认证响应
	if authInfo == nil || authInfo.Auth == nil {
		return fmt.Errorf("invalid response from vault during AWS IAM authentication")
	}

	// 校验 token 生命周期配置合理性
	// token 刷新间隔必须小于 token 实际 TTL，否则还没刷新就过期了
	if authInfo.Auth.LeaseDuration <= v.cfg.Vault.TokenRefreshInterval {
		return fmt.Errorf("token lease duration (%ds) must be greater than token_refresh_interval (%ds). Please increase Vault role token_ttl or decrease token_refresh_interval", authInfo.Auth.LeaseDuration, v.cfg.Vault.TokenRefreshInterval)
	}

	// 使用写锁更新 token 和过期时间
	v.tokenMutex.Lock()
	defer v.tokenMutex.Unlock()
	v.token = authInfo.Auth.ClientToken                                                    // 保存客户端 token
	v.leaseTime = time.Now().Add(time.Duration(authInfo.Auth.LeaseDuration) * time.Second) // 计算过期时间
	v.client.SetToken(v.token)                                                             // 同时更新 API 客户端的 token

	log.Info("Vault authentication successful",
		"token_id", authInfo.Auth.ClientToken,
		"accessor", authInfo.Auth.Accessor,
		"lease_duration", fmt.Sprintf("%ds", authInfo.Auth.LeaseDuration),
		"refresh_interval", fmt.Sprintf("%ds", v.cfg.Vault.TokenRefreshInterval),
		"policies", authInfo.Auth.Policies)
	return nil
}

// StartTokenRefresh 启动后台 Token 自动刷新 goroutine
// refreshInterval: 刷新间隔，参考值 Vault token 剩余时间前 2 分钟
// 通过 context 可以优雅停止刷新循环
func (v *VaultClient) StartTokenRefresh(ctx context.Context, refreshInterval time.Duration) {
	go func() {
		// 创建定时器，按指定间隔触发刷新
		ticker := time.NewTicker(refreshInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				// 收到取消信号，优雅退出
				log.Info("Stopping Vault token refresh")
				return
			case <-ticker.C:
				// 定时触发，重新认证获取新 token
				log.Info("Refreshing Vault token")
				if err := v.Authenticate(); err != nil {
					log.Error("Failed to refresh Vault token", "error", err)
				}
			}
		}
	}()
}

func (v *VaultClient) ValidateToken(token string) (bool, error) {
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		return false, err
	}
	client.SetToken(token)

	secret, err := client.Auth().Token().LookupSelf()
	if err != nil {
		return false, err
	}

	return secret != nil, nil
}

// CreateMasterKey 在 Vault Transit Engine 中创建主密钥
// chain: 链名称（如 eth, btc），用于构建密钥路径
// name: 密钥名称
// keyType: 密钥类型（如 aes256-gcm96, ed25519）
// derived: 是否使用派生密钥（启用后相同输入会生成不同密钥）
func (v *VaultClient) CreateMasterKey(chain, name string, keyType string, derived bool) error {
	// Transit Engine 密钥路径格式: transit/{chain}/keys/{key_name}
	keyPath := fmt.Sprintf("transit/%s/keys/%s", chain, name)

	// 构造创建密钥的请求 payload
	payload := map[string]interface{}{
		"type":    keyType, // 密钥算法类型
		"derived": derived, // 是否启用派生
	}

	// 调用 Vault API 创建密钥
	secret, err := v.client.Logical().Write(keyPath, payload)
	if err != nil {
		// 检查是否是"密钥已存在"错误，如果是则忽略（幂等性处理）
		if isKeyExistsError(err) {
			log.Info("Master key already exists", "chain", chain)
			return nil
		}
		return fmt.Errorf("failed to create master key for chain %s: %w", chain, err)
	}

	// 记录创建结果
	if secret != nil {
		log.Info("Successfully created master key", "chain", chain, "key_name", fmt.Sprintf("%s-master-key", chain))
	} else {
		log.Info("Master key already exists (nil response)", "chain", chain)
	}

	return nil
}

// ListKeys 列出指定链的所有密钥
// chain: 链名称
// 返回: 包含密钥列表的 Secret 对象
func (v *VaultClient) ListKeys(chain string) (*api.Secret, error) {
	// Transit Engine 密钥列表路径: transit/{chain}/keys (使用 LIST 方法)
	keyPath := fmt.Sprintf("transit/%s/keys", chain)
	return v.client.Logical().List(keyPath)
}

// ReadKey 读取指定密钥的详细信息
// chain: 链名称
// keyName: 密钥名称
// 返回: 包含密钥信息的 Secret 对象
func (v *VaultClient) ReadKey(chain, keyName string) (*api.Secret, error) {
	// Transit Engine 密钥读取路径: transit/{chain}/keys/{key_name}
	keyPath := fmt.Sprintf("transit/%s/keys/%s", chain, keyName)
	return v.client.Logical().Read(keyPath)
}

// isKeyExistsError 判断 Vault 返回的错误是否是"密钥已存在"错误
// 用于实现幂等性：密钥已存在时不需要报错
func isKeyExistsError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	// 检查错误信息中是否包含 "already exists" 或 HTTP 400 状态码
	return strings.Contains(errStr, "already exists") || strings.Contains(errStr, "400")
}

// Sign 使用 Vault Transit Engine 对数据进行签名
// chain: 链名称
// keyName: 密钥名称
// data: 要签名的原始数据（字节数组）
// 返回: Base64 编码的签名字符串
func (v *VaultClient) Sign(chain, keyName string, data []byte) (string, error) {
	// Transit Engine 签名路径格式: transit/{chain}/sign/{key_name}
	signPath := fmt.Sprintf("transit/%s/sign/%s", chain, keyName)

	// Vault Transit Engine 要求 input 为十六进制格式的字符串
	payload := map[string]interface{}{
		"input": fmt.Sprintf("%x", data),
	}

	// 调用 Vault API 执行签名
	secret, err := v.client.Logical().Write(signPath, payload)
	if err != nil {
		return "", fmt.Errorf("failed to sign data: %w", err)
	}

	// 验证响应
	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("empty response from Vault during signing")
	}

	// 从响应中提取签名结果
	signature, ok := secret.Data["signature"].(string)
	if !ok {
		return "", fmt.Errorf("invalid signature format in response")
	}

	return signature, nil
}

// Verify 使用 Vault Transit Engine 验证签名
// chain: 链名称
// keyName: 密钥名称
// data: 原始数据（用于验证的哈希值）
// signature: 要验证的签名字符串
// 返回: 签名是否有效
func (v *VaultClient) Verify(chain, keyName string, data []byte, signature string) (bool, error) {
	// Transit Engine 验签路径格式: transit/{chain}/verify/{key_name}
	verifyPath := fmt.Sprintf("transit/%s/verify/%s", chain, keyName)

	// 构造验签请求，包含原始数据和签名
	payload := map[string]interface{}{
		"input":     fmt.Sprintf("%x", data), // 原始数据的十六进制表示
		"signature": signature,               // 要验证的签名
	}

	// 调用 Vault API 执行验签
	secret, err := v.client.Logical().Write(verifyPath, payload)
	if err != nil {
		return false, fmt.Errorf("failed to verify signature: %w", err)
	}

	// 验证响应
	if secret == nil || secret.Data == nil {
		return false, fmt.Errorf("empty response from Vault during verification")
	}

	// 从响应中提取验证结果
	valid, ok := secret.Data["valid"].(bool)
	if !ok {
		return false, fmt.Errorf("invalid verification result format in response")
	}

	return valid, nil
}
