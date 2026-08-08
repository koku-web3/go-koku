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
	Path  string
}

type VaultConfig struct {
	Address              string `toml:"address"`
	MountPath            string `toml:"mount_path"`
	RoleName             string `toml:"role_name"`
	TokenRefreshInterval int    `toml:"token_refresh_interval"`
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
	DEFAULT_PATH = "config/signer.toml"
)

func LoadConfig(path string) (*Config, error) {
	_, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("config file not found: %w", err)
	}

	cfg = &Config{}
	_, err = toml.DecodeFile(path, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}

	cfg.Path = path

	return cfg, nil
}

func GetConfig() *Config {
	return cfg
}
