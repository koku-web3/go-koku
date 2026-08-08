package logko

import (
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	// 通过 glogger.Verbosity(log.FromLegacyLevel(level)) 设置日志级别
	glogger       *GlogHandler
	logOutputFile io.WriteCloser
)

// Setup 使用配置和选项初始化日志
// 如果 cfg 为 nil，则使用默认配置
func Setup(cfg *Config, opts ...Option) error {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	// 应用函数式选项（可覆盖配置文件中的值）
	ApplyOptions(cfg, opts...)

	return setupWithConfig(cfg)
}

// MustSetup 初始化日志，失败则 panic
func MustSetup(cfg *Config, opts ...Option) {
	if err := Setup(cfg, opts...); err != nil {
		panic(err)
	}
}

// SetupFromTOML 从 TOML 文件加载配置并初始化日志
// 相当于先调用 LoadFromTOML 再调用 Setup
func SetupFromTOML(path string, opts ...Option) error {
	cfg, err := LoadFromTOML(path)
	if err != nil {
		return fmt.Errorf("failed to load config from %s: %w", path, err)
	}
	return Setup(cfg, opts...)
}

// MustSetupFromTOML 从 TOML 文件加载配置并初始化日志，失败则 panic
func MustSetupFromTOML(path string, opts ...Option) {
	if err := SetupFromTOML(path, opts...); err != nil {
		panic(err)
	}
}

// setupWithConfig 内部函数，使用配置初始化日志
func setupWithConfig(cfg *Config) error {
	var (
		handler        slog.Handler
		output         io.Writer
		terminalOutput = io.Writer(os.Stderr)
	)

	rotation := cfg.Rotation

	logFile := cfg.FilePath

	// Maximum size in MBs of a single log file
	logMaxSizeMBs := cfg.MaxSizeMB
	if logMaxSizeMBs == 0 {
		logMaxSizeMBs = 100
	}

	// Maximum number of backups
	logMaxBackups := cfg.MaxBackups
	if logMaxBackups == 0 {
		logMaxBackups = 10
	}

	// Maximum age in days of a log file
	logMaxAge := cfg.MaxAge
	if logMaxAge == 0 {
		logMaxAge = 30
	}

	// Whether to compress old log files
	logCompress := cfg.Compress

	// Log format to use (json|logfmt|terminal)
	// default terminal
	logFormat := cfg.Format

	// Logging verbosity: 0=silent, 1=error, 2=warn, 3=info, 4=debug, 5=detail
	verbosity := cfg.Verbosity

	// Per-module verbosity: comma-separated list of <pattern>=<level> (e.g. eth/*=5,p2p=4)
	logVmodule := cfg.Vmodule

	// 该代码片段用于根据命令行参数选择日志的输出位置（文件、终端、或两者），并配置日志文件轮转策略（如轮转文件大小、备份数量、压缩等）。
	if rotation {
		// 配置lumberjack日志轮转器相关参数
		logOutputFile = &lumberjack.Logger{
			Filename:   logFile,
			MaxSize:    logMaxSizeMBs, // 单个日志文件最大MB数
			MaxBackups: logMaxBackups, // 最大备份文件数
			MaxAge:     logMaxAge,     // 文件最大保存天数
			Compress:   logCompress,   // 是否压缩历史日志
		}
		// 同时输出到终端和日志文件
		output = io.MultiWriter(terminalOutput, logOutputFile)
	} else if logFile != "" {
		// 如果关闭了轮转，但设置了日志文件，仅追加写该文件和终端
		var err error
		if logOutputFile, err = os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); err != nil { //nolint: gosec
			return err
		}
		output = io.MultiWriter(logOutputFile, terminalOutput)
	} else {
		// 既未轮转也未指定文件，仅输出到终端
		output = terminalOutput
	}

	switch {
	case logFormat == "json":
		handler = JSONHandler(output)
	case logFormat == "logfmt":
		handler = LogfmtHandler(output)
	case logFormat == "", logFormat == "terminal":

		useColor := (isatty.IsTerminal(os.Stderr.Fd()) || isatty.IsCygwinTerminal(os.Stderr.Fd())) && os.Getenv("TERM") != "dumb"
		if useColor {
			terminalOutput = colorable.NewColorableStderr()
			if logOutputFile != nil {
				output = io.MultiWriter(logOutputFile, terminalOutput)
			} else {
				output = terminalOutput
			}
		}
		handler = NewTerminalHandler(output, useColor)
	default:
		// Unknown log format specified
		return fmt.Errorf("unknown log format: %v", logFormat)
	}

	glogger = NewGlogHandler(handler)

	// logging
	verbosityLevel := FromLegacyLevel(verbosity)
	glogger.Verbosity(verbosityLevel)

	if err := glogger.Vmodule(logVmodule); err != nil {
		return fmt.Errorf("Vmodule error: %v", err)
	}

	SetDefault(NewLogger(glogger))

	return nil
}
