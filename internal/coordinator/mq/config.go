package mq

import "time"

// Config MQ 配置
type Config struct {
	Enable               bool
	URL                  string
	Exchange             string
	ExchangeType         string
	PrefetchCount        int
	QueueAcct0           string
	QueueAcct1           string
	RoutingKeyAcct0      string
	RoutingKeyAcct1      string
	DialTimeoutSec       int
	HeartbeatSec         int
	ReconnectIntervalSec int
}

// DefaultConfig 返回默认配置
func DefaultConfig() Config {
	return Config{
		PrefetchCount:        32,
		DialTimeoutSec:       10,
		HeartbeatSec:         30,
		ReconnectIntervalSec: 5,
		Exchange:             "koku.universal.transfer",
		ExchangeType:         "direct",
		QueueAcct0:           "universal.transfer.acct0",
		QueueAcct1:           "universal.transfer.acct1",
		RoutingKeyAcct0:      "acct0",
		RoutingKeyAcct1:      "acct1",
	}
}

// DialTimeout 返回连接超时 duration
func (c *Config) DialTimeout() time.Duration {
	if c.DialTimeoutSec <= 0 {
		return 10 * time.Second
	}
	return time.Duration(c.DialTimeoutSec) * time.Second
}

// Heartbeat 返回心跳间隔 duration
func (c *Config) Heartbeat() time.Duration {
	if c.HeartbeatSec <= 0 {
		return 30 * time.Second
	}
	return time.Duration(c.HeartbeatSec) * time.Second
}

// ReconnectInterval 返回重连间隔 duration
func (c *Config) ReconnectInterval() time.Duration {
	if c.ReconnectIntervalSec <= 0 {
		return 5 * time.Second
	}
	return time.Duration(c.ReconnectIntervalSec) * time.Second
}
