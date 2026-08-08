package logko

import (
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.MaxSizeMB != 100 {
		t.Errorf("expected MaxSizeMB=100, got %d", cfg.MaxSizeMB)
	}
	if cfg.MaxBackups != 10 {
		t.Errorf("expected MaxBackups=10, got %d", cfg.MaxBackups)
	}
	if cfg.MaxAge != 30 {
		t.Errorf("expected MaxAge=30, got %d", cfg.MaxAge)
	}
	if cfg.Format != "terminal" {
		t.Errorf("expected Format=terminal, got %s", cfg.Format)
	}
	if cfg.Verbosity != 3 {
		t.Errorf("expected Verbosity=3, got %d", cfg.Verbosity)
	}
}

func TestOptionWithFilePath(t *testing.T) {
	cfg := &Config{}
	opt := WithFilePath("/var/log/app.log")
	opt(cfg)

	if cfg.FilePath != "/var/log/app.log" {
		t.Errorf("expected FilePath=/var/log/app.log, got %s", cfg.FilePath)
	}
}

func TestOptionWithRotation(t *testing.T) {
	cfg := &Config{}
	opt := WithRotation()
	opt(cfg)

	if !cfg.Rotation {
		t.Error("expected Rotation=true")
	}
}

func TestOptionWithFormat(t *testing.T) {
	tests := []struct {
		format string
		want   string
	}{
		{"json", "json"},
		{"logfmt", "logfmt"},
		{"terminal", "terminal"},
	}

	for _, tt := range tests {
		cfg := &Config{}
		opt := WithFormat(tt.format)
		opt(cfg)

		if cfg.Format != tt.want {
			t.Errorf("WithFormat(%s): expected %s, got %s", tt.format, tt.want, cfg.Format)
		}
	}
}

func TestOptionWithVerbosity(t *testing.T) {
	tests := []struct {
		level  int
		expect int
	}{
		{0, 0},
		{3, 3},
		{5, 5},
	}

	for _, tt := range tests {
		cfg := &Config{}
		opt := WithVerbosity(tt.level)
		opt(cfg)

		if cfg.Verbosity != tt.expect {
			t.Errorf("WithVerbosity(%d): expected %d, got %d", tt.level, tt.expect, cfg.Verbosity)
		}
	}
}

func TestOptionWithVmodule(t *testing.T) {
	cfg := &Config{}
	opt := WithVmodule("eth/*=5,p2p=4")
	opt(cfg)

	if cfg.Vmodule != "eth/*=5,p2p=4" {
		t.Errorf("expected Vmodule=eth/*=5,p2p=4, got %s", cfg.Vmodule)
	}
}

func TestApplyOptions(t *testing.T) {
	cfg := &Config{}

	ApplyOptions(cfg,
		WithFilePath("/var/log/test.log"),
		WithFormat("json"),
		WithVerbosity(4),
		WithRotation(),
	)

	if cfg.FilePath != "/var/log/test.log" {
		t.Errorf("expected FilePath=/var/log/test.log, got %s", cfg.FilePath)
	}
	if cfg.Format != "json" {
		t.Errorf("expected Format=json, got %s", cfg.Format)
	}
	if cfg.Verbosity != 4 {
		t.Errorf("expected Verbosity=4, got %d", cfg.Verbosity)
	}
	if !cfg.Rotation {
		t.Error("expected Rotation=true")
	}
}

func TestWithJSONFormat(t *testing.T) {
	cfg := &Config{}
	opt := WithJSONFormat()
	opt(cfg)

	if cfg.Format != "json" {
		t.Errorf("expected Format=json, got %s", cfg.Format)
	}
}

func TestWithLogfmtFormat(t *testing.T) {
	cfg := &Config{}
	opt := WithLogfmtFormat()
	opt(cfg)

	if cfg.Format != "logfmt" {
		t.Errorf("expected Format=logfmt, got %s", cfg.Format)
	}
}

func TestWithTerminalFormat(t *testing.T) {
	cfg := &Config{Format: "json"}
	opt := WithTerminalFormat()
	opt(cfg)

	if cfg.Format != "terminal" {
		t.Errorf("expected Format=terminal, got %s", cfg.Format)
	}
}

func TestWithMaxSizeMB(t *testing.T) {
	cfg := &Config{}
	opt := WithMaxSizeMB(200)
	opt(cfg)

	if cfg.MaxSizeMB != 200 {
		t.Errorf("expected MaxSizeMB=200, got %d", cfg.MaxSizeMB)
	}
}

func TestWithMaxBackups(t *testing.T) {
	cfg := &Config{}
	opt := WithMaxBackups(5)
	opt(cfg)

	if cfg.MaxBackups != 5 {
		t.Errorf("expected MaxBackups=5, got %d", cfg.MaxBackups)
	}
}

func TestWithMaxAge(t *testing.T) {
	cfg := &Config{}
	opt := WithMaxAge(7)
	opt(cfg)

	if cfg.MaxAge != 7 {
		t.Errorf("expected MaxAge=7, got %d", cfg.MaxAge)
	}
}

func TestWithCompress(t *testing.T) {
	cfg := &Config{}
	opt := WithCompress()
	opt(cfg)

	if !cfg.Compress {
		t.Error("expected Compress=true")
	}
}
