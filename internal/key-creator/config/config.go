package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Vault VaultConfig `toml:"vault"`
	AWS   AWSConfig   `toml:"aws"`
	Log   LogConfig   `toml:"log"`
	GRPC  GRPCConfig  `toml:"grpc"`
	TLS   TLSConfig   `toml:"tls"`
	Path  string
}

type VaultConfig struct {
	Address              string `toml:"address"`
	MountPath            string `toml:"mount_path"`
	RoleName             string `toml:"role_name"`
	TokenRefreshInterval int    `toml:"token_refresh_interval"`
	CACertFile           string `toml:"vault_ca_cert_file"` // 用于验证 Vault 服务器证书的 CA 证书
}

type AWSConfig struct {
	IAMUserEnable bool   `toml:"iam_user_enable"`
	AccessKey     string `toml:"access_key"`
	SecretKey     string `toml:"secret_key"`
	RoleARN       string `toml:"role_arn"`
}

type GRPCConfig struct {
	Enable bool   `toml:"enable"`
	Host   string `toml:"host"`
	Port   int    `toml:"port"`
}

type TLSConfig struct {
	Enable         bool   `toml:"enable"`
	CACertFile     string `toml:"ca_cert_file"`
	ServerCertFile string `toml:"server_cert_file"`
	ServerKeyFile  string `toml:"server_key_file"`
}

type LogConfig struct {
	Rotation   bool   `toml:"rotation"`
	FilePath   string `toml:"file_path"`
	MaxSizeMB  int    `toml:"max_size_mb"`
	MaxBackups int    `toml:"max_backups"`
	MaxAge     int    `toml:"max_age"`
	Compress   bool   `toml:"compress"`
	Format     string `toml:"format"`
	Verbosity  int    `toml:"verbosity"`
	Vmodule    string `toml:"vmodule"`
}

var cfg *Config

const (
	DEFAULT_PATH = ""
)

func LoadConfig(path string) (*Config, error) {
	if path == "" {
		return nil, fmt.Errorf("config file path is required")
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("config file not found: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("config path is a directory, expected a file: %s", path)
	}

	cfg = &Config{}
	_, err = toml.DecodeFile(path, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}

	cfg.Path = path

	// TLS 配置校验（默认强制开启）
	if cfg.TLS.Enable {
		if cfg.TLS.CACertFile == "" {
			return nil, fmt.Errorf("tls.ca_cert_file is required when tls is enabled")
		}
		if cfg.TLS.ServerCertFile == "" {
			return nil, fmt.Errorf("tls.server_cert_file is required when tls is enabled")
		}
		if cfg.TLS.ServerKeyFile == "" {
			return nil, fmt.Errorf("tls.server_key_file is required when tls is enabled")
		}
	}

	return cfg, nil
}

func GetConfig() *Config {
	return cfg
}
