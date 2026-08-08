package logko

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

// LoadFromTOML 从 TOML 文件加载配置
// 支持两种格式:
//   - [log] 命名空间格式
//   - 扁平顶级格式
func LoadFromTOML(path string) (*Config, error) {
	return LoadFromFile(path)
}

// LoadFromFile 从 TOML 文件加载配置
func LoadFromFile(path string) (*Config, error) {
	content, err := readFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	return loadFromTOMLString(content)
}

// LoadFromReader 从 io.Reader 加载配置
func LoadFromReader(r io.Reader) (*Config, error) {
	content, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read input: %w", err)
	}

	return loadFromTOMLString(string(content))
}

// LoadFromBytes 从字节 slice 加载配置
func LoadFromBytes(data []byte) (*Config, error) {
	return loadFromTOMLString(string(data))
}

// readFile 读取文件内容
func readFile(path string) (string, error) {
	data, err := os.ReadFile(path) //nolint: gosec,G304
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// loadFromTOMLString 从 TOML 字符串加载配置
// 支持两种格式:
//   - [log] 命名空间格式: [log] format = "json"
//   - 扁平顶级格式: format = "json"
func loadFromTOMLString(content string) (*Config, error) {
	// 检测是否有 [log] 节
	hasLogSection := false
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[log]") {
			hasLogSection = true
			break
		}
	}

	var lc *logConfig
	var err error

	if hasLogSection {
		// 使用 [log] 命名空间格式
		lc, err = loadLogConfigWithSection(content)
	} else {
		// 使用扁平格式
		lc, err = loadLogConfigFlat(content)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}

	return loadFromLogConfig(lc), nil
}

// loadLogConfigWithSection 从包含 [log] 节的内容加载配置
func loadLogConfigWithSection(content string) (*logConfig, error) {
	type configWrapper struct {
		Log logConfig `toml:"log"`
	}

	var wrapper configWrapper
	_, err := toml.Decode(content, &wrapper)
	if err != nil {
		return nil, err
	}

	return &wrapper.Log, nil
}

// loadLogConfigFlat 从扁平格式内容加载配置
func loadLogConfigFlat(content string) (*logConfig, error) {
	lc := &logConfig{}
	_, err := toml.Decode(content, lc)
	if err != nil {
		return nil, err
	}

	return lc, nil
}
