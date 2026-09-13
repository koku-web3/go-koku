# Go-Koku

Go-Koku 是一个基于 HashiCorp Vault 的去中心化密钥管理中间件服务，专为区块链交易签名场景设计。它作为链签名服务与 KMS（Vault）之间的桥梁，为上游各链的签名服务提供统一的密钥管理接口。

![服务架构示意图](docs/images/architecture.png)

---

## 目录

- [项目概述](#项目概述)
- [核心架构](#核心架构)
- [服务详解](#服务详解)
  - [Coordinator（协调器）](#1-coordinator协调器)
  - [Signer（签名服务）](#2-signer签名服务)
  - [KeyCreator（密钥生成服务）](#3-keycreator密钥生成服务)
- [BIP-44 密钥派生规范](#bip-44-密钥派生规范)
- [安全设计](#安全设计)
- [目录结构](#目录结构)
- [快速启动](#快速启动)
- [Docker 启动流程](#docker-启动流程)
- [mTLS 配置指南](docs/mtls.md)
- [服务依赖关系](#服务依赖关系)
- [API 参考](#api-参考)

---

## 项目概述

Go-Koku 实现了以下核心功能：

| 功能 | 描述 |
|------|------|
| 密钥生命周期管理 | 创建、查询、删除密钥 |
| HD 密钥派生 | 支持 BIP-44 标准，支持 ECDSA（secp256k1、p256）、Ed25519 等多种签名算法 |
| 交易签名 | 通过 Signer 服务完成区块链交易签名 |
| 统一转账 | 支持跨链统一转账接口 |
| 审计日志 | 记录所有密钥操作，支持合规审计 |

---

## 核心架构

Go-Koku 采用微服务架构，由三个核心 gRPC 服务组成：

```
┌─────────────────────────────────────────────────────────────────────┐
│                          上游业务系统                                 │
└─────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         Coordinator (协调器)                          │
│                     gRPC: 127.0.0.1:50051                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌───────────┐ │
│  │  gRPC Server │  │  MQ Consumer │  │ Key Service │  │Transfer Svc│ │
│  └──────────────┘  └──────────────┘  └──────────────┘  └───────────┘ │
│                              │                    │                 │
│         ┌────────────────────┼────────────────────┘                 │
│         │                    │                                        │
│         ▼                    ▼                                        │
│  ┌──────────────┐    ┌──────────────┐                               │
│  │ KeyCreator    │    │   Signer     │                               │
│  │   Client      │    │   Client     │                               │
│  └──────────────┘    └──────────────┘                               │
└─────────────────────────────────────────────────────────────────────┘
        │                        │
        ▼                        ▼
┌───────────────────┐    ┌───────────────────┐    ┌───────────────────┐
│  KeyCreator       │    │     Signer        │    │   TxBuilder       │
│  gRPC: :50053     │    │  gRPC: :50052     │    │  (External)       │
│                   │    │                   │    │                   │
│  ┌─────────────┐  │    │  ┌─────────────┐  │    │                   │
│  │ KMS Service │  │    │  │ KMS Service │  │    │                   │
│  └─────────────┘  │    │  └─────────────┘  │    │                   │
└───────────────────┘    └───────────────────┘    └───────────────────┘
        │                        │
        └────────┬───────────────┘
                 ▼
        ┌───────────────────┐
        │   HashiCorp Vault │
        │   Transit Engine  │
        └───────────────────┘
                 ▲
        ┌────────┴────────┐
        │  MySQL 8.0     │    ┌───────────────────┐
        │  (持久化存储)    │    │    RabbitMQ       │
        └─────────────────┘    │  (消息队列)        │
                                └───────────────────┘
```

---

## 服务详解

### 1. Coordinator（协调器）

**服务地址**：`127.0.0.1:50051`

Coordinator 是整个系统的协调中心，负责：
- 接收上游业务系统的 gRPC 请求
- 协调 KeyCreator 和 Signer 服务完成密钥生成和签名
- 管理密钥生命周期（Genesis、创建、查询）
- 处理统一转账请求（Universal Transfer）
- 通过 RabbitMQ 异步处理转账消息

#### 核心模块

| 模块 | 路径 | 职责 |
|------|------|------|
| `grpc` | `internal/coordinator/grpc/` | gRPC 服务端，处理来自上游的请求 |
| `service` | `internal/coordinator/service/` | 业务逻辑层，包含 KeyService 和 TransferService |
| `repository` | `internal/coordinator/repository/` | 数据访问层，负责 MySQL 操作 |
| `mq` | `internal/coordinator/mq/` | RabbitMQ 消费者，处理异步转账消息 |
| `infra` | `internal/coordinator/infra/` | 外部服务客户端（Signer、KeyCreator、TxBuilder） |

#### gRPC 接口

```protobuf
service Coordinator {
  rpc HealthCheck(HealthCheckRequest) returns (HealthCheckResponse);
  rpc Genesis(GenesisRequest) returns (GenesisResponse);
  rpc CreateOperationalKey(CreateKeyRequest) returns (CreateKeyResponse);
  rpc CreateUserKey(CreateKeyRequest) returns (CreateKeyResponse);
  rpc VerifyAddress(VerifyAddressRequest) returns (VerifyAddressResponse);
  rpc VerifyContractAddress(VerifyContractAddressRequest) returns (VerifyContractAddressResponse);
  rpc CheckSufficientBalance(CheckSufficientBalanceRequest) returns (CheckSufficientBalanceResponse);
  rpc UniversalTransfer(UniversalTransferRequest) returns (UniversalTransferResponse);
}
```

#### 工作流程

**Genesis（初始化链主密钥）**：
```
1. 接收 GenesisRequest（chain_code, key_type）
2. 调用 KeyCreator.Genesis 生成 HD 主密钥和派生的核心密钥
3. 将密钥信息存储到 MySQL（MasterKey、CoreKey 表）
4. 返回 GenesisResponse
```

**创建子密钥（CreateOperationalKey/CreateUserKey）**：
```
1. 接收 CreateKeyRequest（chain_code, count）
2. 从数据库获取 CoreKey 和 MasterKey
3. 调用 KeyCreator.CreateOperationalKey/CreateUserKey 派生子密钥
4. 调用 TxBuilder.ConvertAddress 将公钥转换为区块链地址
5. 将子密钥存储到 MySQL（Key 表）
6. 返回地址列表
```

**统一转账（Universal Transfer）**：
```
1. 接收转账请求或从 RabbitMQ 消费消息
2. 验证地址合法性
3. 检查余额是否充足
4. 调用 TxBuilder.BuildSignRawData 构建待签名数据
5. 调用 Signer 服务签名交易
6. 调用 TxBuilder.TxBroadcast 广播交易
7. 记录审计日志
```

#### 消息队列配置

Coordinator 监听 RabbitMQ 的两个队列处理转账消息：

| 队列 | Routing Key | 用途 |
|------|-------------|------|
| `universal.transfer.acct0` | `acct0` | 运营账户转账（归集、出账） |
| `universal.transfer.acct1` | `acct1` | 用户账户转账（归集） |

---

### 2. Signer（签名服务）

**服务地址**：`127.0.0.1:50052`

Signer 是专门负责交易签名的服务，遵循最小权限原则：
- **私钥明文仅在 Signer 内存中短暂存在**
- 签名完成后立即清零
- 所有签名操作记录审计日志

#### gRPC 接口

```protobuf
service Signer {
  rpc HealthCheck(HealthCheckRequest) returns (HealthCheckResponse);
  rpc SignAcct0(SignRequest) returns (SignResponse);  // 运营账户签名
  rpc SignAcct1(SignRequest) returns (SignResponse);  // 用户账户签名
}
```

#### 签名流程

```
1. 接收 SignRequest（chain_code, bip44_path, message, priv_key_ciphertext）
2. 调用 Vault KMS 解密私钥密文
3. 使用对应算法（ECDSA/Ed25519）对消息签名
4. 立即清零私钥明文内存
5. 返回签名结果（hex 格式）
```

#### 支持的密钥类型

| KeyType | 算法 | 用途 |
|---------|------|------|
| `ecdsa-secp256k1` | ECDSA over secp256k1 | 比特币、以太坊等 |
| `ecdsa-p256` | ECDSA over P-256 (NIST P-256) | 特定场景 |
| `eddsa-ed25519` | Ed25519 | Solana、Near 等 |

---

### 3. KeyCreator（密钥生成服务）

**服务地址**：`127.0.0.1:50053`

KeyCreator 负责 HD 密钥的生成和派生，核心功能：
- 生成 HD 主密钥（符合 BIP-39/BIP-32 标准）
- 按 BIP-44 规范派生核心密钥
- 派生子密钥供业务使用
- 所有密钥通过 Vault Transit Engine 加密存储

#### gRPC 接口

```protobuf
service KeyCreator {
  rpc HealthCheck(HealthCheckRequest) returns (HealthCheckResponse);
  rpc Genesis(GenesisRequest) returns (GenesisResponse);
  rpc CreateOperationalKey(CreateKeyRequest) returns (CreateKeyResponse);
  rpc CreateUserKey(CreateKeyRequest) returns (CreateKeyResponse);
}
```

#### Genesis 流程（生成链主密钥）

```
1. 生成随机 HD 主密钥种子（bip32.Key）
2. 按 BIP-44 派生：
   - m/44'/coinType'/0'/0/0  → 运营账户主密钥
   - m/44'/coinType'/1'/0/0  → 用户账户主密钥
3. 使用 Vault Transit Engine 加密3个密钥
4. 返回加密后的密钥密文和 BIP-44 路径
```

#### 创建子密钥流程

```
1. 从数据库获取 CoreKey（运营/用户）的加密密文
2. 调用 Vault 解密得到 bip32.Key
3. 按 BIP-44 派生第5层（address_index）子密钥
4. 将子密钥私钥转换为指定算法的格式
5. 加密后返回（密文、公钥、BIP-44 路径）
```

---

## BIP-44 密钥派生规范

Go-Koku 严格遵循 [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki) 标准：

```
m / purpose' / coinType' / account' / change / address_index
```

| 层级 | 值 | 含义 |
|------|-----|------|
| `purpose` | 44' | BIP-44 标准 |
| `coinType` | 因链而异 | BTC=0', ETH=60', TRX=195' |
| `account` | 0 或 1 | 0=运营账户, 1=用户账户 |
| `change` | 0 | 0=外部地址, 1=找零地址（暂不支持） |
| `address_index` | N | 地址索引，从0开始递增 |

### 各链 coinType 参考

| 链 | coinType | 示例路径 |
|----|----------|---------|
| Bitcoin | 0' | `m/44'/0'/0'/0/0` |
| Ethereum | 60' | `m/44'/60'/0'/0/0` |
| TRON | 195' | `m/44'/195'/0'/0/0` |

### 密钥用途分类

| Account | 用途 | 场景 |
|---------|------|------|
| 0 (OPERATIONAL) | 运营密钥 | 归集、出账、热钱包 |
| 1 (USER) | 用户密钥 | 用户充值地址、归集 |

---

## 安全设计

### 密钥安全

1. **最小暴露原则**：私钥明文仅在签名/生成瞬间存在于内存
2. **内存清零**：使用后立即清零敏感数据
3. **Vault Transit Engine**：所有密钥静态加密存储
4. **BIP-44 派生**：支持无限子密钥，无需暴露主密钥

### 传输安全

1. **gRPC over TCP**：服务间通信
2. **AWS IAM 认证**：KeyCreator/Signer 与 Vault 之间的认证
3. **TLS（生产环境）**：建议配置 TLS 证书

### 审计追踪

1. **AuditLog 表**：记录所有密钥操作
2. **TraceID**：全链路追踪
3. **请求哈希**：防止篡改

---

## 目录结构

```
go-koku/
├── cmd/                          # 服务入口
│   ├── coordinator/              # Coordinator 服务
│   │   └── main.go
│   ├── signer/                   # Signer 服务
│   │   └── main.go
│   └── key-creator/              # KeyCreator 服务
│       └── main.go
├── internal/                     # 内部包
│   ├── coordinator/              # Coordinator 服务实现
│   │   ├── config/               # 配置加载
│   │   ├── grpc/                # gRPC 服务端
│   │   ├── infra/               # 外部依赖客户端
│   │   │   ├── db/              # MySQL 客户端
│   │   │   ├── keycreator/      # KeyCreator gRPC 客户端
│   │   │   ├── signer/          # Signer gRPC 客户端
│   │   │   └── txbuilder/       # TxBuilder gRPC 客户端
│   │   ├── model/               # 数据库模型
│   │   ├── mq/                  # RabbitMQ 消费者
│   │   ├── repository/          # 数据访问层
│   │   └── service/             # 业务逻辑层
│   ├── signer/                   # Signer 服务实现
│   │   ├── config/              # 配置
│   │   ├── grpc/                # gRPC 服务端
│   │   └── kms/                 # Vault KMS 封装
│   └── key-creator/              # KeyCreator 服务实现
│       ├── config/              # 配置
│       ├── grpc/                # gRPC 服务端
│       └── kms/                 # Vault KMS 封装
├── pkg/                          # 公共包
│   ├── proto/                   # 生成的 protobuf 代码
│   │   ├── coordinator/
│   │   ├── signer/
│   │   ├── key-creator/
│   │   └── txbuilder/
│   ├── hdwallet/                # HD 钱包实现
│   ├── keyutil/                 # 密钥工具
│   ├── securestore/             # 安全存储
│   │   └── algorithm/           # 签名算法实现
│   └── vault/                   # Vault 客户端封装
├── config/                       # 服务配置文件
│   ├── coordinator.toml
│   ├── signer.toml
│   └── keycreator.toml
├── migrations/                   # 数据库迁移脚本
├── proto/                       # Protobuf 定义文件
│   ├── coordinator.proto
│   ├── signer.proto
│   ├── keycreator.proto
│   └── txbuilder.proto
├── docker-compose.yml            # Docker 编排配置
└── Dockerfile                    # Docker 镜像构建
```

---

## 快速启动

### 前置条件

- Go 1.21+
- MySQL 8.0
- RabbitMQ 3.x
- HashiCorp Vault（已配置 Transit Engine）

### 1. 初始化数据库

```bash
# 执行数据库初始化脚本（创建数据库和插入初始数据）
mysql -h 127.0.0.1 -u koku -pkoku_pwd < scripts/sql/001_init.sql

# 或分步执行：
mysql -h 127.0.0.1 -u root -proot_pwd < scripts/sql/001_init.sql
```

#### 初始化脚本说明 (`scripts/sql/001_init.sql`)

该脚本完成以下操作：

1. **创建数据库**
   ```sql
   CREATE DATABASE IF NOT EXISTS kokudb DEFAULT CHARACTER SET utf8mb4 DEFAULT COLLATE utf8mb4_unicode_ci;
   ```

2. **创建 chains 表**（如果不存在）

3. **插入初始区块链配置数据**
   - Ethereum Sepolia 测试网：
     - `chain_code`: ethereum
     - `base_coin`: eth
     - `rpc_url`: https://ethereum-sepolia-rpc.publicnode.com
     - `explorer_url`: https://sepolia.etherscan.io/
     - `confirmation_count`: 12
     - `tx_builder_serv_grpc`: http://127.0.0.1:8001

### 2. 配置 Vault Transit Engine

参考 [internal/kms-vault/README.md](internal/kms-vault/README.md) 完成 Vault 配置：

```bash
# 启用 Transit 引擎
vault secrets enable -path=transit/core transit
vault secrets enable -path=transit/operations transit
vault secrets enable -path=transit/user transit

# 启用 AWS Auth
vault auth enable aws

# 创建 Vault Role（关联 AWS IAM）
curl --header "X-Vault-Token: <root_token>" \
     --request POST \
     --data '{"role": "bitcoin-client", "arn": "arn:aws:iam::<AWS_ACCOUNT>:role/vault-auth-role", "policies": ["bitcoin-policy"]}' \
     http://127.0.0.1:8200/v1/auth/aws/role/bitcoin-client
```

### 3. 启动服务

```bash
# 启动 Signer
go run cmd/signer/main.go -config config/signer.toml

# 启动 KeyCreator
go run cmd/key-creator/main.go -config config/keycreator.toml

# 启动 Coordinator
go run cmd/coordinator/main.go -config config/coordinator.toml
```

---

## Docker 启动流程

### 架构说明

Docker Compose 部署包含以下服务：

| 服务 | 端口 | 说明 |
|------|------|------|
| `mysql` | 3306 | MySQL 8.0 数据库 |
| `rabbitmq` | 5672, 15672 | RabbitMQ 消息队列 |
| `coordinator` | 50051 | 协调器服务 |
| `signer` | 50052 | 签名服务 |
| `key-creator` | 50053 | 密钥生成服务 |

> **注意**：TxBuilder 服务为外部依赖，需要自行部署或修改配置指向现有服务。

### 启动步骤

#### 1. 生成 mTLS 证书

```bash
./scripts/gen-certs.sh
```

#### 2. 构建 Docker 镜像

```bash
# 在项目根目录执行
docker build -t go-koku:latest .
```

#### 3. 启动服务

```bash
docker compose up -d
```

所有服务的 gRPC 通信均强制启用 mTLS 双向认证，详见 [mTLS 配置指南](docs/mtls.md)。

#### 4. 准备配置文件

创建 Docker 配置文件（如 `config/coordinator.docker.toml`）：

```toml
[grpc]
host = "0.0.0.0"
port = 50051

[signer]
address = "signer:50052"

[keycreator]
address = "key-creator:50053"

[txbuilder]
dial_timeout = 10

[txbuilder.keepalive]
time = 30
timeout = 10
permit_without_stream = true

[txbuilder.circuit_breaker]
failure_threshold = 5
recovery_window = 30

[txbuilder.chains.btc]
address = "host.docker.internal:50101"

[txbuilder.chains.eth]
address = "host.docker.internal:50102"

[txbuilder.chains.tron]
address = "host.docker.internal:50103"

[mq]
url = "amqp://guest:guest@rabbitmq:5672/"
exchange = "koku.universal.transfer"
exchange_type = "direct"
prefetch_count = 32
queue_acct0 = "universal.transfer.acct0"
queue_acct1 = "universal.transfer.acct1"
routing_key_acct0 = "acct0"
routing_key_acct1 = "acct1"
dial_timeout_sec = 10
heartbeat_sec = 30
reconnect_interval_sec = 5

[db]
host = "mysql"
port = 3306
user = "koku"
password = "koku_pwd"
database = "koku"
max_open_conns = 1000
max_idle_conns = 1000

[log]
rotation = true
file_path = ""
max_size_mb = 100
max_backups = 10
max_age = 30
compress = true
format = "terminal"
verbosity = 3
```

#### 3. 启动服务

```bash
# 启动所有服务
docker compose up -d

# 查看服务状态
docker compose ps

# 查看日志
docker compose logs -f coordinator
docker compose logs -f signer
docker compose logs -f key-creator
```

#### 4. 验证服务

```bash
# 检查 Coordinator 健康状态
grpcurl -plaintext localhost:50051 grpc.reflection.v1.ServerReflection/ServerReflectionInfo || \
grpcurl -plaintext localhost:50051 coordinator.Coordinator/HealthCheck

# 检查 Signer 健康状态
grpcurl -plaintext localhost:50052 coordinator.Coordinator/HealthCheck

# 检查 KeyCreator 健康状态
grpcurl -plaintext localhost:50053 coordinator.Coordinator/HealthCheck
```

#### 5. 停止服务

```bash
# 停止所有服务（保留数据卷）
docker compose down

# 停止并删除数据卷（清空数据）
docker compose down -v
```

### 访问管理界面

| 服务 | 地址 | 凭据 |
|------|------|------|
| RabbitMQ Management | http://localhost:15672 | guest/guest |
| MySQL | localhost:3306 | koku/koku_pwd |

---

## 服务依赖关系

```
启动顺序（按依赖关系）：
1. mysql         → 数据库，coordinator 依赖
2. rabbitmq      → 消息队列，coordinator 依赖
3. signer        → 签名服务，coordinator 调用
4. key-creator   → 密钥生成，coordinator 调用
5. coordinator   → 协调器，接收上游请求

外部依赖（需自行部署）：
- Vault Server   → 密钥加密/解密
- TxBuilder      → 交易构造和广播（每条链一个实例）
```

---

## API 参考

详细 API 文档请参考各服务目录下的 README：

- [Coordinator API](internal/coordinator/README.md)
- [Signer Proto](proto/signer.proto)
- [KeyCreator Proto](proto/keycreator.proto)
- [TxBuilder Proto](proto/txbuilder.proto)

---

## License

MIT License
