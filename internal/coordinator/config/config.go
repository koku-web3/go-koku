package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	AWS        AWSConfig        `toml:"aws"`
	Log        LogConfig        `toml:"log"`
	GRPC       GRPCConfig       `toml:"grpc"`
	TLS        TLSConfig        `toml:"tls"`
	Signer     SignerConfig     `toml:"signer"`
	KeyCreator KeyCreatorConfig `toml:"keycreator"`
	TxBuilder  TxBuilderConfig  `toml:"txbuilder"`
	DB         DBConfig         `toml:"db"`
	MQ         MQConfig         `toml:"mq"`
	Path       string
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

// TLSConfig coordinator 服务端 TLS 配置，同时作为调用下游服务时的客户端证书
type TLSConfig struct {
	Enable         bool   `toml:"enable"`
	CACertFile     string `toml:"ca_cert_file"`
	ServerCertFile string `toml:"server_cert_file"`
	ServerKeyFile  string `toml:"server_key_file"`
}

// TLSClientSettings 客户端 TLS 设置（server_name 指向下游服务的证书 CN/SAN）
// 证书复用 cfg.TLS 中的 ServerCertFile/ServerKeyFile
type TLSClientSettings struct {
	ServerName string `toml:"server_name"`
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

// Signer grpc地址配置
type SignerConfig struct {
	Address   string            `toml:"address"` // Signer gRPC 服务地址，如 "localhost:50051"
	TLSClient TLSClientSettings `toml:"tls"`
}

// Key Creator grpc地址配置
type KeyCreatorConfig struct {
	Address   string            `toml:"address"` // Key Creator gRPC 服务地址，如 "localhost:50051"
	TLSClient TLSClientSettings `toml:"tls"`
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

// TxBuilderConfig TxBuilder 客户端配置
//
// 单 conn 模型下只关心 gRPC 连接参数（keepalive）与熔断器，
// 不再有连接池字段（MaxConnsPerChain / MaxTotalConns / MaxIdleTime / EvictInterval）。
type TxBuilderConfig struct {
	DialTimeout    int                    `toml:"dial_timeout"`
	Keepalive      KeepaliveConfig        `toml:"keepalive"`
	CircuitBreaker CircuitBreakerConfig   `toml:"circuit_breaker"`
	Chains         map[string]ChainConfig `toml:"chains"`
}

// KeepaliveConfig gRPC HTTP/2 keepalive 配置
type KeepaliveConfig struct {
	Time                int  `toml:"time"`
	Timeout             int  `toml:"timeout"`
	PermitWithoutStream bool `toml:"permit_without_stream"`
}

// CircuitBreakerConfig 熔断器配置
type CircuitBreakerConfig struct {
	FailureThreshold int `toml:"failure_threshold"`
	RecoveryWindow   int `toml:"recovery_window"`
}

// ChainConfig 链配置
type ChainConfig struct {
	Address string `toml:"address"`
}

// MQConfig MQ 配置
type MQConfig struct {
	URL                  string `toml:"url"`
	Exchange             string `toml:"exchange"`
	ExchangeType         string `toml:"exchange_type"`
	PrefetchCount        int    `toml:"prefetch_count"`
	QueueAcct0           string `toml:"queue_acct0"`
	QueueAcct1           string `toml:"queue_acct1"`
	RoutingKeyAcct0      string `toml:"routing_key_acct0"`
	RoutingKeyAcct1      string `toml:"routing_key_acct1"`
	DialTimeoutSec       int    `toml:"dial_timeout_sec"`
	HeartbeatSec         int    `toml:"heartbeat_sec"`
	ReconnectIntervalSec int    `toml:"reconnect_interval_sec"`
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

	// 设置 MQ 默认值
	if cfg.MQ.DialTimeoutSec == 0 {
		cfg.MQ.DialTimeoutSec = 10
	}
	if cfg.MQ.HeartbeatSec == 0 {
		cfg.MQ.HeartbeatSec = 30
	}
	if cfg.MQ.ReconnectIntervalSec == 0 {
		cfg.MQ.ReconnectIntervalSec = 5
	}
	if cfg.MQ.PrefetchCount == 0 {
		cfg.MQ.PrefetchCount = 32
	}

	// TLS 配置校验（强制开启）
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

	// 客户端 TLS 只校验 server_name（证书复用 cfg.TLS）
	if cfg.TLS.Enable && cfg.KeyCreator.TLSClient.ServerName == "" {
		return nil, fmt.Errorf("keycreator.tls.server_name is required when tls is enabled")
	}
	if cfg.TLS.Enable && cfg.Signer.TLSClient.ServerName == "" {
		return nil, fmt.Errorf("signer.tls.server_name is required when tls is enabled")
	}

	return cfg, nil
}

func GetConfig() *Config {
	return cfg
}
