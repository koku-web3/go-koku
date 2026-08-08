package logko

import (
	"strings"
	"testing"
)

// assertFullConfig 通用配置断言，减少测试代码重复
func assertFullConfig(t *testing.T, cfg *Config) {
	t.Helper()
	if cfg.FilePath != "/var/log/app.log" {
		t.Errorf("expected FilePath=/var/log/app.log, got %s", cfg.FilePath)
	}
	if !cfg.Rotation {
		t.Error("expected Rotation=true")
	}
	if cfg.MaxSizeMB != 50 {
		t.Errorf("expected MaxSizeMB=50, got %d", cfg.MaxSizeMB)
	}
	if cfg.MaxBackups != 5 {
		t.Errorf("expected MaxBackups=5, got %d", cfg.MaxBackups)
	}
	if cfg.MaxAge != 7 {
		t.Errorf("expected MaxAge=7, got %d", cfg.MaxAge)
	}
	if !cfg.Compress {
		t.Error("expected Compress=true")
	}
	if cfg.Format != "json" {
		t.Errorf("expected Format=json, got %s", cfg.Format)
	}
	if cfg.Verbosity != 4 {
		t.Errorf("expected Verbosity=4, got %d", cfg.Verbosity)
	}
	if cfg.Vmodule != "eth/*=5" {
		t.Errorf("expected Vmodule=eth/*=5, got %s", cfg.Vmodule)
	}
}

func TestLoadFromBytes(t *testing.T) {
	tomlContent := `
file_path = "/var/log/app.log"
rotation = true
max_size_mb = 50
max_backups = 5
max_age = 7
compress = true
format = "json"
verbosity = 4
vmodule = "eth/*=5"
`

	cfg, err := LoadFromBytes([]byte(tomlContent))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertFullConfig(t, cfg)
}

func TestLoadFromBytesDefaults(t *testing.T) {
	// 只设置部分配置，其他应该使用默认值
	tomlContent := `
format = "json"
`

	cfg, err := LoadFromBytes([]byte(tomlContent))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 检查默认值
	if cfg.MaxSizeMB != 100 {
		t.Errorf("expected MaxSizeMB=100, got %d", cfg.MaxSizeMB)
	}
	if cfg.MaxBackups != 10 {
		t.Errorf("expected MaxBackups=10, got %d", cfg.MaxBackups)
	}
	if cfg.MaxAge != 30 {
		t.Errorf("expected MaxAge=30, got %d", cfg.MaxAge)
	}
	// json 覆盖了默认的 terminal
	if cfg.Format != "json" {
		t.Errorf("expected Format=json, got %s", cfg.Format)
	}
	// verbosity 应该是默认值 3
	if cfg.Verbosity != 3 {
		t.Errorf("expected Verbosity=3, got %d", cfg.Verbosity)
	}
}

func TestLoadFromBytesInvalidTOML(t *testing.T) {
	invalidContent := `
file_path = "/var/log/test.log
rotation = invalid_bool
`

	_, err := LoadFromBytes([]byte(invalidContent))
	if err == nil {
		t.Error("expected error for invalid TOML")
	}
}

func TestLoadFromReader(t *testing.T) {
	tomlContent := `
format = "logfmt"
verbosity = 2
`

	cfg, err := LoadFromReader(strings.NewReader(tomlContent))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Format != "logfmt" {
		t.Errorf("expected Format=logfmt, got %s", cfg.Format)
	}
	if cfg.Verbosity != 2 {
		t.Errorf("expected Verbosity=2, got %d", cfg.Verbosity)
	}
}

func TestLoadFromBytesWithLogSection(t *testing.T) {
	// 测试 [log] 命名空间格式
	tomlContent := `
[log]
file_path = "/var/log/app.log"
rotation = true
max_size_mb = 50
max_backups = 5
max_age = 7
compress = true
format = "json"
verbosity = 4
vmodule = "eth/*=5"
`

	cfg, err := LoadFromBytes([]byte(tomlContent))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	assertFullConfig(t, cfg)
}

func TestLoadFromBytesWithLogSectionPartial(t *testing.T) {
	// 测试 [log] 节中只有部分配置
	tomlContent := `
[log]
format = "json"
verbosity = 5
`

	cfg, err := LoadFromBytes([]byte(tomlContent))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Format != "json" {
		t.Errorf("expected Format=json, got %s", cfg.Format)
	}
	if cfg.Verbosity != 5 {
		t.Errorf("expected Verbosity=5, got %d", cfg.Verbosity)
	}
	// 其他使用默认值
	if cfg.MaxSizeMB != 100 {
		t.Errorf("expected MaxSizeMB=100, got %d", cfg.MaxSizeMB)
	}
}

func TestLoadFromBytesMixedFormat(t *testing.T) {
	// 测试混合配置（[log] 节和其他配置）
	tomlContent := `
app_name = "myapp"

[log]
format = "terminal"
verbosity = 4

[database]
host = "localhost"
`

	cfg, err := LoadFromBytes([]byte(tomlContent))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Format != "terminal" {
		t.Errorf("expected Format=terminal, got %s", cfg.Format)
	}
	if cfg.Verbosity != 4 {
		t.Errorf("expected Verbosity=4, got %d", cfg.Verbosity)
	}
}
