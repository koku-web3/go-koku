package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	AWS    AWSConfig    `toml:"aws"`
	Log    LogConfig    `toml:"log"`
	GRPC   GRPCConfig   `toml:"grpc"`
	Signer SignerConfig `toml:"signer"`
	DB     DBConfig     `toml:"db"`
	Path   string
}

type AWSConfig struct {
	IAMUserEnable bool   `toml:"iam_user_enable"`
	AccessKey     string `toml:"access_key"`
	SecretKey     string `toml:"secret_key"`
	RoleARN       string `toml:"role_arn"`
}

type GRPCConfig struct {
	Host string `toml:"host"`
	Port int    `toml:"port"`
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

// SignerConfig Signer 服务配置
type SignerConfig struct {
	Address string `toml:"address"` // Signer gRPC 服务地址，如 "localhost:50051"
}

// DBConfig 数据库配置
type DBConfig struct {
	Host         string `toml:"host"`
	Port         int    `toml:"port"`
	User         string `toml:"user"`
	Password     string `toml:"password"`
	Database     string `toml:"database"`
	MaxOpenConns int    `toml:"max_open_conns"`
	MaxIdleConns int    `toml:"max_idle_conns"`
}

var cfg *Config

const (
	DEFAULT_PATH = "config/coordinator.toml"
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
