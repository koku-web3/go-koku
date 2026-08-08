package chain

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/koku-web3/go-koku/internal/coordinator/config"
	"github.com/koku-web3/go-koku/internal/coordinator/vault"
	log "github.com/koku-web3/go-koku/pkg/logko"
)

// ChainService 链服务结构体
// 封装 Vault 客户端，提供 HTTP API 接口用于密钥管理和签名操作
type ChainService struct {
	vaultClient *vault.VaultClient // Vault 客户端实例，用于密钥操作
}

// NewChainService 创建链服务实例
// 初始化 Vault 客户端并完成首次认证
func NewChainService(cfg *config.Config) (*ChainService, error) {
	// 创建 Vault 客户端
	vaultClient, err := vault.NewVaultClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	// 立即进行首次认证，确保服务启动时 Vault 连接正常
	if err := vaultClient.Authenticate(); err != nil {
		return nil, fmt.Errorf("failed to authenticate with Vault: %w", err)
	}

	return &ChainService{
		vaultClient: vaultClient,
	}, nil
}

// StartTokenRefresh 启动 Token 自动刷新
// 从配置读取刷新间隔，启动后台 goroutine 定期刷新 Vault Token
func (s *ChainService) StartTokenRefresh(ctx context.Context) {
	// 从配置获取刷新间隔（秒），转换为 time.Duration
	interval := time.Duration(s.vaultClient.GetConfig().Vault.TokenRefreshInterval) * time.Second
	s.vaultClient.StartTokenRefresh(ctx, interval)
}

// GetVaultClient 获取 Vault 客户端实例
func (s *ChainService) GetVaultClient() *vault.VaultClient {
	return s.vaultClient
}

// CreateMasterKey 创建主密钥
// POST /keys/master
// 请求体: { "chain": "eth", "name": "mykey", "type": "ecdsa-p256", "derived": true }
func (s *ChainService) CreateMasterKey(c *gin.Context) {
	// 解析请求体，binding:"required" 确保必填字段存在
	var request struct {
		Chain   string `json:"chain" binding:"required"`
		Name    string `json:"name" binding:"required"`
		Type    string `json:"type" binding:"required"`
		Derived bool   `json:"derived"`
	}

	// 参数绑定失败返回 400 Bad Request
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 调用 Vault 创建密钥
	if err := s.vaultClient.CreateMasterKey(request.Chain, request.Name, request.Type, request.Derived); err != nil {
		log.Error("Failed to create master key", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 查询密钥详情获取 public_key
	result, err := s.vaultClient.ReadKey(request.Chain, request.Name)
	if err != nil {
		log.Error("Failed to read key for public_key", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	var publicKey string
	if result != nil && result.Data != nil {
		if keysMap, ok := result.Data["keys"].(map[string]interface{}); ok {
			for _, v := range keysMap {
				if keyInfo, ok := v.(map[string]interface{}); ok {
					if pk, ok := keyInfo["public_key"].(string); ok {
						publicKey = pk
						break
					}
				}
			}
		}
	}

	// 返回成功响应
	c.JSON(http.StatusOK, gin.H{
		"message":    fmt.Sprintf("Master key created successfully for chain: %s", request.Chain),
		"chain":      request.Chain,
		"name":       request.Name,
		"type":       request.Type,
		"derived":    request.Derived,
		"public_key": publicKey,
	})
}

// ListKeys 列出指定链的所有密钥
// GET /keys?chain=eth
// 查询参数: chain (必填) - 链名称
func (s *ChainService) ListKeys(c *gin.Context) {
	// 从查询参数获取 chain
	chain := c.Query("chain")
	if chain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "chain parameter is required"})
		return
	}

	// 调用 Vault 列出密钥
	result, err := s.vaultClient.ListKeys(chain)
	if err != nil {
		log.Error("Failed to list keys", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// 返回 Vault 响应（包含密钥列表）
	c.JSON(http.StatusOK, result)
}

// ReadKey 读取指定密钥的详细信息
// GET /keys/:key_name?chain=eth
// 路径参数: key_name - 密钥名称
// 查询参数: chain (必填) - 链名称
func (s *ChainService) ReadKey(c *gin.Context) {
	chain := c.Query("chain")
	if chain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "chain parameter is required"})
		return
	}

	keyName := c.Param("key_name")
	if keyName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "key_name parameter is required"})
		return
	}

	// 调用 Vault 读取密钥详情
	result, err := s.vaultClient.ReadKey(chain, keyName)
	if err != nil {
		log.Error("Failed to read key", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, result)
}

// HealthCheck 健康检查接口
// GET /health
// 用于 Kubernetes readiness/liveness probe
func (s *ChainService) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
	})
}

// SignMessage 对数据进行签名
// POST /sign
// 请求体: { "chain": "eth", "key_name": "mykey", "data": "0x1234..." }
func (s *ChainService) SignMessage(c *gin.Context) {
	var request struct {
		Chain   string `json:"chain" binding:"required"`
		KeyName string `json:"key_name" binding:"required"`
		Data    string `json:"data" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 将十六进制字符串解码为字节数组（支持 0x 前缀）
	data, err := hexDecode(request.Data)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid hex data: %v", err)})
		return
	}

	// 调用 Vault 执行签名
	signature, err := s.vaultClient.Sign(request.Chain, request.KeyName, data)
	if err != nil {
		log.Error("Failed to sign message", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"chain":         request.Chain,
		"key_name":      request.KeyName,
		"signature":     signature,                 // Base64 格式的原始签名
		"signature_hex": signatureToHex(signature), // 十六进制格式签名，方便调试
	})
}

// VerifySignature 验证签名有效性
// POST /verify
// 请求体: { "chain": "eth", "key_name": "mykey", "data": "0x1234...", "signature": "vault:v1:..." }
func (s *ChainService) VerifySignature(c *gin.Context) {
	var request struct {
		Chain     string `json:"chain" binding:"required"`
		KeyName   string `json:"key_name" binding:"required"`
		Data      string `json:"data" binding:"required"`
		Signature string `json:"signature" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 将十六进制字符串解码为字节数组
	data, err := hexDecode(request.Data)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid hex data: %v", err)})
		return
	}

	// 调用 Vault 验证签名
	valid, err := s.vaultClient.Verify(request.Chain, request.KeyName, data, request.Signature)
	if err != nil {
		log.Error("Failed to verify signature", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"chain":    request.Chain,
		"key_name": request.KeyName,
		"valid":    valid, // true 表示签名有效
	})
}

// hexDecode 将十六进制字符串解码为字节数组
// 支持带或不带 "0x" 前缀
func hexDecode(s string) ([]byte, error) {
	// 跳过可选的 0x 前缀
	if len(s) >= 2 && s[:2] == "0x" {
		s = s[2:]
	}
	// 十六进制字符串长度必须为偶数
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd length hex string")
	}
	result := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		var b byte
		// 逐字符转换，每两位十六进制字符组成一个字节
		for j := 0; j < 2; j++ {
			c := s[i+j]
			b <<= 4 // 左移 4 位，为新字符腾出空间
			switch {
			case c >= '0' && c <= '9':
				b |= c - '0'
			case c >= 'a' && c <= 'f':
				b |= c - 'a' + 10
			case c >= 'A' && c <= 'F':
				b |= c - 'A' + 10
			default:
				return nil, fmt.Errorf("invalid hex character: %c", c)
			}
		}
		result[i/2] = b
	}
	return result, nil
}

// signatureToHex 将 Vault 返回的签名转换为十六进制格式
// Vault 签名格式: "vault:v1:{base64编码数据}"
// 转换为: "0x{十六进制数据}" 方便前端使用
func signatureToHex(signature string) string {
	const prefix = "vault:v1:"
	// 如果签名格式不正确，直接返回原始值
	if len(signature) <= len(prefix) {
		return signature
	}

	// 去掉前缀，取出 Base64 数据
	b64Data := signature[len(prefix):]
	// Base64 解码
	decoded, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return signature
	}

	// 转换为十六进制并添加 0x 前缀
	return hexEncode(decoded)
}

// hexEncode 将字节数组编码为十六进制字符串（带 0x 前缀）
func hexEncode(data []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(data)*2)
	for i, b := range data {
		// 高 4 位和低 4 位分别转换
		result[i*2] = hexChars[b>>4]
		result[i*2+1] = hexChars[b&0x0f]
	}
	return "0x" + string(result)
}
