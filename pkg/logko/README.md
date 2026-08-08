# logko - Go Logging Package

一个功能丰富的 Go 日志库，基于 `log/slog` 构建，提供多种输出格式、日志轮转、模块级别过滤等功能。

## 功能特性

- **多种输出格式**: JSON、Logfmt、Terminal（彩色）
- **日志轮转**: 支持 lumberjack 日志轮转，自动管理日志文件大小和备份
- **模块级别过滤**: 通过 vmodule 对不同模块设置不同的日志级别
- **glog 兼容**: 支持类似 Google glog 的 Vmodule 过滤语法
- **线程安全**: 使用 sync.RWMutex 保证并发安全
- **灵活配置**: 支持 TOML 配置文件和函数式选项两种配置方式

## 安装

```bash
go get github.com/koku-web3/logko@latest
```

## 文件说明

| 文件 | 说明 |
|------|------|
| `config.go` | 配置结构体定义，包含 `Config` 结构体和默认值配置 |
| `option.go` | 函数式选项模式实现，用于灵活配置日志参数 |
| `loader.go` | TOML 配置文件加载器 |
| `appearance.go` | 日志初始化入口，包含 `Setup` 函数 |
| `logger.go` | Logger 接口定义和日志级别常量 |
| `handler.go` | 多种 Handler 实现 (JSON、Logfmt、Terminal) |
| `handler_glog.go` | GlogHandler，实现模块级别日志过滤 (vmodule) |
| `format.go` | 日志格式化工具，处理特殊类型输出 |
| `root.go` | 全局日志函数 (Info、Debug、Error 等) |

## 快速开始

### 方式一：TOML 配置文件

支持两种配置格式：

**格式一：[log] 命名空间（推荐）**

```toml
[log]
format = "json"
verbosity = 3
rotation = true
file_path = "/var/log/app.log"
max_size_mb = 100
max_backups = 10
max_age = 30
compress = true
vmodule = "eth/*=5,p2p=4"
```

**格式二：扁平格式**

```toml
format = "json"
verbosity = 3
rotation = true
file_path = "/var/log/app.log"
max_size_mb = 100
max_backups = 10
max_age = 30
compress = true
vmodule = "eth/*=5,p2p=4"
```

使用配置:

```go
package main

import logko "github.com/koku-web3/logko"

func main() {
    cfg, err := logko.LoadFromTOML("config.toml")
    if err != nil {
        panic(err)
    }

    if err := logko.Setup(cfg); err != nil {
        panic(err)
    }

    logko.Info("Application started")
}
```

**简化用法（推荐）**：使用 `SetupFromTOML` 一行代码搞定：

```go
package main

import logko "github.com/koku-web3/logko"

func main() {
    // 一行代码加载配置并初始化
    if err := logko.SetupFromTOML("config.toml"); err != nil {
        panic(err)
    }

    // 还可以用选项覆盖部分配置
    // logko.MustSetupFromTOML("config.toml", logko.WithVerbosity(5))

    logko.Info("Application started")
}
```

### 方式二：代码配置

```go
package main

import logko "github.com/koku-web3/logko"

func main() {
    if err := logko.Setup(&logko.Config{
        Format:    "json",
        Verbosity: 3,
        FilePath:  "/var/log/app.log",
        Rotation:  true,
        MaxSizeMB: 100,
        MaxBackups: 10,
        MaxAge:    30,
        Compress:  true,
    }); err != nil {
        panic(err)
    }

    logko.Info("Application started")
}
```

### 方式三：函数式选项

```go
package main

import logko "github.com/koku-web3/logko"

func main() {
    logko.Setup(nil,
        logko.WithFormat("json"),
        logko.WithVerbosity(4),
        logko.WithFilePath("/var/log/app.log"),
        logko.WithRotation(),
    )

    logko.Info("Application started")
}
```

### 方式四：混合使用

```go
package main

import logko "github.com/koku-web3/logko"

func main() {
    // 从配置文件加载
    cfg, _ := logko.LoadFromTOML("config.toml")

    // 使用选项覆盖部分配置
    logko.Setup(cfg,
        logko.WithVerbosity(5),
    )

    logko.Info("Application started")
}
```

## 日志级别

| 级别 | 值 | 说明 |
|------|-----|------|
| Trace | -8 | 最详细级别 |
| Debug | -4 | 调试信息 |
| Info | 0 | 一般信息 |
| Warn | 4 | 警告信息 |
| Error | 8 | 错误信息 |
| Crit | 12 | 严重错误，记录后程序退出 |

Verbosity 参数映射:

| Verbosity | 对应级别 |
|------------|----------|
| 0 | Silent (静默) |
| 1 | Error |
| 2 | Warn |
| 3 | Info (默认) |
| 4 | Debug |
| 5 | Trace |

## 日志格式

### JSON 格式

```json
{"t":"2026-08-02T15:19:03.851975+08:00","lvl":"info","msg":"test message","key":"value"}
```

### Logfmt 格式

```
t=2026-08-02T15:19:03+08:00 lvl=info msg="test message" key=value
```

### Terminal 格式

```
[INFO ] [15:19:03] test message                        key=value
```

## 日志轮转配置

| 参数 | 说明 | 默认值 |
|------|------|--------|
| FilePath | 日志文件路径 | - |
| Rotation | 是否启用轮转 | false |
| MaxSizeMB | 单个文件最大 MB 数 | 100 |
| MaxBackups | 最大备份文件数 | 10 |
| MaxAge | 文件保留天数 | 30 |
| Compress | 是否压缩历史日志 | false |

## Vmodule 模块过滤

使用 `vmodule` 可以对不同模块设置不同的日志级别:

```go
logko.Setup(&logko.Config{
    Vmodule: "eth/*=5,p2p=4,chain=3",
})
```

语法: `pattern=level,pattern=level,...`

- `eth/*=5`: eth 目录下所有文件使用 trace 级别
- `p2p=4`: p2p 模块使用 debug 级别
- `chain=3`: chain 模块使用 info 级别

## 使用日志

### 基本用法

```go
logko.Trace("trace message")
logko.Debug("debug message")
logko.Info("info message")
logko.Warn("warning message")
logko.Error("error message")
```

### 带上下文

```go
logko.Info("user logged in", "user_id", 123, "ip", "192.168.1.1")
```

### 创建子 Logger

```go
logger := logko.New("module", "auth")
logger.Info("user logged in", "user_id", 123)
```

### 检查级别是否启用

```go
if logko.Root().Enabled(ctx, logko.LevelDebug) {
    logko.Debug("expensive debug info")
}
```

## 配置选项

| 选项函数 | 说明 |
|----------|------|
| `WithFilePath(path)` | 设置日志文件路径 |
| `WithRotation()` | 启用日志轮转 |
| `WithMaxSizeMB(size)` | 设置单文件最大 MB |
| `WithMaxBackups(n)` | 设置最大备份数 |
| `WithMaxAge(days)` | 设置文件保留天数 |
| `WithCompress()` | 启用日志压缩 |
| `WithFormat(format)` | 设置输出格式 (json/logfmt/terminal) |
| `WithVerbosity(level)` | 设置日志级别 |
| `WithVmodule(vmodule)` | 设置模块过滤规则 |
| `WithJSONFormat()` | 快捷方式：设置为 JSON 格式 |
| `WithLogfmtFormat()` | 快捷方式：设置为 logfmt 格式 |
| `WithTerminalFormat()` | 快捷方式：设置为终端格式 |



## 常用开发命令

```bash
# 编译检查（验证代码无语法/类型错误）
go build ./...

# 深度检查（比编译更严格的静态分析）
go vet ./...

# 运行所有测试
go test ./...

# 运行测试（带详细输出）
go test ./... -v

# 运行测试（显示覆盖率）
go test ./... -cover

# 检查代码格式
gofmt -l .

# 格式化代码
gofmt -w .

# 清理依赖（添加缺失，移除未使用）
go mod tidy
```

**路径通配符说明：**
| 符号 | 含义 |
|------|------|
| `.` | 当前目录 |
| `...` | 当前目录及所有子目录 |

例如 `go build ./...` 会编译当前目录及所有子包。

## 依赖

- Go 1.25+
- github.com/BurntSushi/toml (配置解析)
- github.com/mattn/go-colorable (彩色终端)
- github.com/mattn/go-isatty (终端检测)
- gopkg.in/natefinch/lumberjack.v2 (日志轮转)
- github.com/holiman/uint256 (可选，用于特殊类型格式化)

## License

MIT
