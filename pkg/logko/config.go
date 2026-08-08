package logko

// Config 日志配置选项
type Config struct {
	FilePath string // 日志文件路径，为空则不写文件
	Format   string // 日志格式: json, logfmt, terminal (默认)
	Vmodule  string // 模块级别过滤，如: eth/*=5,p2p=4

	MaxSizeMB  int // 单个日志文件最大 MB 数，默认 100
	MaxBackups int // 最大备份文件数，默认 10
	MaxAge     int // 文件最大保存天数，默认 30
	Verbosity  int // 日志级别: 0=silent, 1=error, 2=warn, 3=info, 4=debug, 5=trace

	Rotation bool // 是否启用日志轮转
	Compress bool // 是否压缩历史日志

}

// logConfig 是用于 TOML 解析的中间结构体，使用下划线命名
type logConfig struct {
	Format     string `toml:"format"`
	Vmodule    string `toml:"vmodule"`
	FilePath   string `toml:"file_path"`
	Verbosity  int    `toml:"verbosity"`
	MaxSizeMB  int    `toml:"max_size_mb"`
	MaxBackups int    `toml:"max_backups"`
	MaxAge     int    `toml:"max_age"`
	Rotation   bool   `toml:"rotation"`
	Compress   bool   `toml:"compress"`
}

// DefaultConfig 返回默认配置
func DefaultConfig() *Config {
	return &Config{
		MaxSizeMB:  100,
		MaxBackups: 10,
		MaxAge:     30,
		Format:     "terminal",
		Verbosity:  3, // info level
	}
}

// loadFromLogConfig 从 logConfig 加载到 Config
func loadFromLogConfig(lc *logConfig) *Config {
	cfg := DefaultConfig()

	if lc.Format != "" {
		cfg.Format = lc.Format
	}
	if lc.Verbosity != 0 {
		cfg.Verbosity = lc.Verbosity
	}
	if lc.Vmodule != "" {
		cfg.Vmodule = lc.Vmodule
	}
	if lc.FilePath != "" {
		cfg.FilePath = lc.FilePath
	}
	if lc.Rotation {
		cfg.Rotation = lc.Rotation
	}
	if lc.MaxSizeMB != 0 {
		cfg.MaxSizeMB = lc.MaxSizeMB
	}
	if lc.MaxBackups != 0 {
		cfg.MaxBackups = lc.MaxBackups
	}
	if lc.MaxAge != 0 {
		cfg.MaxAge = lc.MaxAge
	}
	if lc.Compress {
		cfg.Compress = lc.Compress
	}

	return cfg
}
