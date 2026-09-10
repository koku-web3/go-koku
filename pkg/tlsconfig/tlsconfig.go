package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
)

// ServerConfig 服务端 TLS 配置
type ServerConfig struct {
	CACertFile     string // CA 证书，用于验证客户端证书
	ServerCertFile string // 服务端证书
	ServerKeyFile  string // 服务端私钥
}

// ClientConfig 客户端 TLS 配置
type ClientConfig struct {
	CACertFile     string // CA 证书，用于验证服务端证书
	ClientCertFile string // 客户端证书
	ClientKeyFile  string // 客户端私钥
	ServerName     string // 校验服务端证书的 ServerName/SAN
}

// LoadServerConfig 从 PEM 文件加载服务端 TLS 配置
// 返回 *tls.Config，可直接传给 gRPC credentials.NewTLS()
func LoadServerConfig(cfg ServerConfig) (*tls.Config, error) {
	roots := x509.NewCertPool()
	if err := addFileToPool(roots, cfg.CACertFile); err != nil {
		return nil, err
	}

	cert, err := tls.LoadX509KeyPair(cfg.ServerCertFile, cfg.ServerKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server cert/key (%s, %s): %w",
			cfg.ServerCertFile, cfg.ServerKeyFile, err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    roots,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}, nil
}

// LoadClientConfig 从 PEM 文件加载客户端 TLS 配置
// 返回 *tls.Config，可直接传给 gRPC credentials.NewTLS()
func LoadClientConfig(cfg ClientConfig) (*tls.Config, error) {
	roots := x509.NewCertPool()
	if err := addFileToPool(roots, cfg.CACertFile); err != nil {
		return nil, err
	}

	cert, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client cert/key (%s, %s): %w",
			cfg.ClientCertFile, cfg.ClientKeyFile, err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
		ServerName:   cfg.ServerName,
	}, nil
}

// NewServerCreds 从 ServerConfig 创建 gRPC 服务端 credentials
func NewServerCreds(cfg ServerConfig) (credentials.TransportCredentials, error) {
	tlsCfg, err := LoadServerConfig(cfg)
	if err != nil {
		return nil, err
	}
	return credentials.NewTLS(tlsCfg), nil
}

// NewClientCreds 从 ClientConfig 创建 gRPC 客户端 credentials
func NewClientCreds(cfg ClientConfig) (credentials.TransportCredentials, error) {
	tlsCfg, err := LoadClientConfig(cfg)
	if err != nil {
		return nil, err
	}
	return credentials.NewTLS(tlsCfg), nil
}

func addFileToPool(pool *x509.CertPool, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read cert file %s: %w", path, err)
	}
	if !pool.AppendCertsFromPEM(data) {
		return fmt.Errorf("failed to append cert from %s: no certificates found", path)
	}
	return nil
}
