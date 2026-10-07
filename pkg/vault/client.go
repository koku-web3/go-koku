package vault

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	log "github.com/koku-web3/logko"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/hashicorp/vault/api"
	vaultaws "github.com/hashicorp/vault/api/auth/aws"
)

type Cfg struct {
	// hashicorp vault 相关配置
	Address              string
	MountPath            string
	RoleName             string
	TokenRefreshInterval int
	CACertFile           string // 用于验证 Vault 服务器证书的 CA 证书

	// AWS IAM 相关配置
	AWS AwsCfg
}

type AwsCfg struct {
	IAMUserEnable bool
	AccessKey     string
	SecretKey     string
	RoleARN       string
}

// VaultClient Vault 客户端结构体
// 用于管理 Vault 连接、认证和密钥操作
type VaultClient struct {
	client     *api.Client  // Vault API 客户端实例
	cfg        *Cfg         // 应用配置
	token      string       // 当前有效的 Vault Token
	tokenMutex sync.RWMutex // 读写锁，保护 token 的并发访问
	leaseTime  time.Time    // Token 的过期时间
}

// NewVaultClient 创建新的 Vault 客户端实例
// 使用配置中的地址初始化 Vault 连接
func NewVaultClient(cfg *Cfg) (*VaultClient, error) {
	// 获取默认的 Vault 配置（包含默认的 TLS 设置等）
	vaultConfig := api.DefaultConfig()
	// 设置 Vault 服务器地址
	vaultConfig.Address = cfg.Address

	// 如果配置了 CA 证书，设置 TLS 配置
	if cfg.CACertFile != "" {
		caCert, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA cert file %s: %w", cfg.CACertFile, err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert from file %s", cfg.CACertFile)
		}

		// 创建自定义的 HTTP 客户端，配置 TLS
		httpClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
					RootCAs:    caCertPool,
				},
			},
		}
		vaultConfig.HttpClient = httpClient

		log.Info("Vault client TLS configured with CA cert", "ca_cert_file", cfg.CACertFile)
	}

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

func (v *VaultClient) GetConfig() *Cfg {
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
			log.Error("Failed to unset AWS_ACCESS_KEY_ID", "error", err)
		}
		if err := os.Unsetenv("AWS_SECRET_ACCESS_KEY"); err != nil {
			log.Error("Failed to unset AWS_SECRET_ACCESS_KEY", "error", err)
		}
		if err := os.Unsetenv("AWS_SESSION_TOKEN"); err != nil {
			log.Error("Failed to unset AWS_SESSION_TOKEN", "error", err)
		}
	}()

	log.Info("Authenticating with Vault", "role_name", v.cfg.RoleName, "mount_path", v.cfg.MountPath)

	// 创建 Vault AWS Auth 方法实例
	// WithRole 指定 Vault 中配置的 AWS Auth Role 名称
	// WithMountPath 指定 AWS Auth Method 的挂载路径（默认是 aws）
	auth, err := vaultaws.NewAWSAuth(
		vaultaws.WithRole(v.cfg.RoleName),
		vaultaws.WithMountPath(v.cfg.MountPath),
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
	if authInfo.Auth.LeaseDuration <= v.cfg.TokenRefreshInterval {
		return fmt.Errorf("token lease duration (%ds) must be greater than token_refresh_interval (%ds). Please increase Vault role token_ttl or decrease token_refresh_interval", authInfo.Auth.LeaseDuration, v.cfg.TokenRefreshInterval)
	}

	// 使用写锁更新 token 和过期时间
	v.tokenMutex.Lock()
	defer v.tokenMutex.Unlock()
	v.token = authInfo.Auth.ClientToken                                                    // 保存客户端 token
	v.leaseTime = time.Now().Add(time.Duration(authInfo.Auth.LeaseDuration) * time.Second) // 计算过期时间
	v.client.SetToken(v.token)                                                             // 同时更新 API 客户端的 token

	log.Info("Vault authentication successful", "token_id", "[REDACTED]", "lease_duration", authInfo.Auth.LeaseDuration, "refresh_interval", v.cfg.TokenRefreshInterval, "policies", authInfo.Auth.Policies)
	return nil
}

// TokenRefreshSchedule 启动后台 Token 自动刷新 goroutine
// refreshInterval: 刷新间隔，参考值 Vault token 剩余时间前 2 分钟
// 通过 context 可以优雅停止刷新循环
func (v *VaultClient) TokenRefreshSchedule(ctx context.Context, refreshInterval time.Duration) {
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
