package txbuilder

// Config gRPC 客户端配置
type Config struct {
	// DialTimeout 表示建立 gRPC 连接的超时时间（秒）
	DialTimeout int

	// KeepaliveTime 表示客户端发送 keepalive ping 的间隔时间（秒）
	KeepaliveTime int
	// KeepaliveTimeout 表示等待 keepalive ack 的超时时间（秒）
	KeepaliveTimeout int
	// PermitWithoutStream 指定当没有活动的 gRPC 流时，客户端是否仍然允许发送 keepalive ping。举例来说：
	// 如果设置为 true，则即使当前没有任何正在进行的请求，客户端也会定期发送 keepalive ping 到服务器，用来检测连接是否存活，这可以帮助尽早发现连接异常并重连，适合对连接实时性要求较高的场景。
	// 如果设置为 false，则只有在有活跃请求流时才会发送 keepalive ping，这样可以减少网络流量，但在连接空闲期间可能更晚发现连接已经断开。
	// 例如：在一个服务对可用性要求极高时，建议将此值设为 true；而对于普通或长时间空闲的服务，可以考虑用 false。
	PermitWithoutStream bool

	// MinConnectTimeout gRPC 重连时的最小超时时间（秒）
	MinConnectTimeout int
	// MaxConnectTimeout gRPC 重连时的最大超时时间（秒）
	MaxConnectTimeout int

	// CircuitBreakerThreshold 定义熔断器被触发所需的连续失败次数阈值。
	// 也就是说，如果一次RPC调用失败会记录一次，只有当失败的次数达到该阈值后，熔断器才会进入"打开"状态，不再允许新的请求，直接快速返回错误。
	// 例如：如果设置为5，则只有当连续发生5次失败后，熔断器才会被触发并熔断，防止继续向后端发起请求，保护系统。
	CircuitBreakerThreshold int

	// CircuitBreakerWindow 指定熔断器判断窗口的时间长度，单位为秒。在该时间窗口内累计的失败次数会被统计来判断是否触发熔断。
	// 如果时间窗口为30秒，则每隔30秒重新计算失败数，避免长时间前的失败影响现有判断。
	// 例子：假设CircuitBreakerWindow为60，Threshold为5，则只有在连续60秒内发生5次失败才会打开熔断器；
	// 超过60秒的老失败记录将被清除，不再累计。
	CircuitBreakerWindow int
}

func DefaultConfig() Config {
	return Config{
		DialTimeout:             10,
		KeepaliveTime:           30,
		KeepaliveTimeout:        10,
		PermitWithoutStream:     true,
		MinConnectTimeout:       5,
		MaxConnectTimeout:       30,
		CircuitBreakerThreshold: 5,
		CircuitBreakerWindow:    30,
	}
}
