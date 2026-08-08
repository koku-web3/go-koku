package logko

// Option 配置选项函数类型，用于函数式选项模式
type Option func(*Config)

// WithFilePath 设置日志文件路径
func WithFilePath(path string) Option {
	return func(c *Config) {
		c.FilePath = path
	}
}

// WithRotation 启用日志轮转
func WithRotation() Option {
	return func(c *Config) {
		c.Rotation = true
	}
}

// WithMaxSizeMB 设置单个日志文件最大 MB 数
func WithMaxSizeMB(size int) Option {
	return func(c *Config) {
		c.MaxSizeMB = size
	}
}

// WithMaxBackups 设置最大备份文件数
func WithMaxBackups(n int) Option {
	return func(c *Config) {
		c.MaxBackups = n
	}
}

// WithMaxAge 设置文件最大保存天数
func WithMaxAge(days int) Option {
	return func(c *Config) {
		c.MaxAge = days
	}
}

// WithCompress 启用日志文件压缩
func WithCompress() Option {
	return func(c *Config) {
		c.Compress = true
	}
}

// WithFormat 设置日志格式 (json, logfmt, terminal)
func WithFormat(format string) Option {
	return func(c *Config) {
		c.Format = format
	}
}

// WithVerbosity 设置日志级别 (0=silent, 1=error, 2=warn, 3=info, 4=debug, 5=trace)
func WithVerbosity(level int) Option {
	return func(c *Config) {
		c.Verbosity = level
	}
}

// WithVmodule 设置模块级别过滤
func WithVmodule(vmodule string) Option {
	return func(c *Config) {
		c.Vmodule = vmodule
	}
}

// WithJSONFormat 设置为 JSON 格式输出
func WithJSONFormat() Option {
	return func(c *Config) {
		c.Format = "json"
	}
}

// WithLogfmtFormat 设置为 logfmt 格式输出
func WithLogfmtFormat() Option {
	return func(c *Config) {
		c.Format = "logfmt"
	}
}

// WithTerminalFormat 设置为终端格式输出（默认）
func WithTerminalFormat() Option {
	return func(c *Config) {
		c.Format = "terminal"
	}
}

// ApplyOptions 将多个选项应用到配置
func ApplyOptions(cfg *Config, opts ...Option) {
	for _, opt := range opts {
		opt(cfg)
	}
}
