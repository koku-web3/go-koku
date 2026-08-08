# Coordinator

## 概述

Coordinator 协调器 是一个基于 HashiCorp Vault 的密钥管理中间服务。它作为链签名服务与 KMS（Vault）之间的桥梁，为上游各链的签名服务提供统一的密钥管理接口。

**核心功能**：
- 密钥生命周期管理：创建、查询、删除密钥
- 交易签名：支持 ECDSA（secp256k1、p256）、Ed25519 等多种签名算法
- 签名验证：验证签名有效性
- 多链支持：通过配置不同的链名称（如 ethereum、bitcoin、tron、solana 等）管理各链密钥

![服务架构示意图](docs/images/coordinator-architecture.png)

## 目录结构

```
coordinator/
├── config/
│   ├── config.go
│   └── config.toml
├── grpc/
│   ├── proto/
│   │   └── service.proto
│   ├── server.go
│   └── client.go
├── middleware/
│   └── httploger.go
├── chain/
│   ├── service.go
│   └── service_test.go
├── vault/
│   └── client.go
├── go.mod
├── go.sum
├── main.go
└── README.md
```

**服务地址**：`http://{host}:{port}`

**认证方式**：通过请求头 `X-Vault-Token` 传递 Vault 访问令牌

**Base URL**：`http://localhost:8080`

---

## 目录

- [HTTP 接口](#1-健康检查)
  - [健康检查](#1-健康检查)
  - [创建主密钥](#2-创建主密钥)
  - [获取密钥列表](#3-获取密钥列表)
  - [获取密钥详情](#4-获取密钥详情)
  - [交易签名](#5-交易签名)
  - [验证签名](#6-验证签名)
- [gRPC 接口](#7-grpc-接口)
  - [gRPC 概述](#71-grpc-概述)
  - [gRPC 服务定义](#72-grpc-服务定义)
  - [接口说明](#73-接口说明)
  - [客户端调用示例](#74-客户端调用示例)

---

## 1. 健康检查

检查服务运行状态。

### 请求

```http
GET /health
```

### 请求示例

```bash
curl -X GET "http://localhost:8080/health"
```

### 响应


| 参数名称   | 类型     | 描述                 |
| ------ | ------ | ------------------ |
| status | string | 服务状态，`ok` 表示服务正常运行 |




### 响应示例

```json
{
    "status": "ok"
}
```



### 错误码


| HTTP 状态码 | 说明      |
| -------- | ------- |
| 200      | 请求成功    |
| 500      | 服务器内部错误 |


---



## 2. 创建主密钥

在指定区块链网络中创建一个新的主密钥。

### 请求

```http
POST /api/keys
Content-Type: application/json
```



### 请求参数


| 参数名称  | 类型     | 必选  | 描述                    |
| ----- | ------ | --- | --------------------- |
| chain | string | 是   | 区块链网络名称（如 `ethereum`） |
| name  | string | 是   | 密钥名称，不可重复             |
| type  | string | 是   | 密钥类型（如 `ecdsa-p256`、`ed25519`） |
| derived | bool  | 否   | 是否启用派生密钥，默认 `false`  |




### 请求示例

```bash
curl -X POST "http://localhost:8080/api/keys" \
  -H "Content-Type: application/json" \
  -d '{
    "chain": "ethereum",
    "name": "master-key-01",
    "type": "ecdsa-p256",
    "derived": false
  }'
```



### 响应


| 参数名称    | 类型     | 描述      |
| ------- | ------ | ------- |
| message | string | 操作结果描述  |
| chain   | string | 区块链网络名称 |
| name    | string | 密钥名称    |
| type    | string | 密钥类型    |
| derived | bool   | 是否启用派生密钥 |
| public_key | string | 公钥（PEM 格式） |




### 响应示例

```json
{
    "message": "Master key created successfully for chain: ethereum",
    "chain": "ethereum",
    "name": "master-key-01",
    "type": "ecdsa-p256",
    "derived": false,
    "public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPyqi36XMqhZOGZEpkBFtpFTICKBH\nrQReXwi+FHnrKTdeansfVl6brB4vlKiZy2bxOOrrH1dfL7qZeLelbLC42Q==\n-----END PUBLIC KEY-----\n"
}
```



### 错误码


| HTTP 状态码 | 错误信息                  | 说明          |
| -------- | --------------------- | ----------- |
| 400      | Invalid request       | 请求参数缺失或格式错误 |
| 500      | already exists        | 密钥已存在       |
| 500      | Internal Server Error | 服务器内部错误     |


---



## 3. 获取密钥列表

获取指定区块链网络下的所有密钥列表。

### 请求

```http
GET /api/keys?chain={chain}
```



### 请求参数


| 参数名称  | 类型     | 必选  | 描述      |
| ----- | ------ | --- | ------- |
| chain | string | 是   | 区块链网络名称 |




### 请求示例

```bash
curl -X GET "http://localhost:8080/api/keys?chain=ethereum"
```



### 响应


| 参数名称 | 类型           | 描述     |
| ---- | ------------ | ------ |
| keys | array string | 密钥名称列表 |




### 响应示例

```json
{
    "keys": [
        "master-key-01",
        "master-key-02"
    ]
}
```



### 错误码


| HTTP 状态码 | 错误信息                        | 说明         |
| -------- | --------------------------- | ---------- |
| 400      | chain parameter is required | chain 参数必填 |
| 500      | Internal Server Error       | 服务器内部错误    |


---



## 4. 获取密钥详情

获取指定密钥的详细信息。

### 请求

```http
GET /api/keys/{key_name}?chain={chain}
```



### 请求参数


| 参数名称     | 类型     | 必选  | 描述             |
| -------- | ------ | --- | -------------- |
| chain    | string | 是   | 区块链网络名称        |
| key_name | string | 是   | 密钥名称（URL 路径参数） |




### 请求示例

```bash
curl -X GET "http://localhost:8080/api/keys/master-key-01?chain=ethereum"
```



### 响应


| 参数名称 | 类型     | 描述              |
| ---- | ------ | --------------- |
| -    | object | Vault 返回的密钥详细信息 |




### 响应示例

```json
{
    "request_id": "abc123",
    "version": 1,
    "name": "master-key-01",
    "creation_time": "2024-01-15T10:30:00Z",
    "keys": {
        "1": "vault:v1:xxxxx..."
    },
    "min_version": 1,
    "latest_version": 1
}
```



### 错误码


| HTTP 状态码 | 错误信息                           | 说明            |
| -------- | ------------------------------ | ------------- |
| 400      | chain parameter is required    | chain 参数必填    |
| 400      | key_name parameter is required | key_name 参数必填 |
| 500      | Internal Server Error          | 服务器内部错误       |


---



## 5. 交易签名

使用指定密钥对消息进行签名。

### 请求

```http
POST /api/sign
Content-Type: application/json
```



### 请求参数


| 参数名称     | 类型     | 必选  | 描述               |
| -------- | ------ | --- | ---------------- |
| chain    | string | 是   | 区块链网络名称（如 `ethereum`） |
| key_name | string | 是   | 密钥名称             |
| data     | string | 是   | 要签名的数据（hex 编码）   |




### 请求示例

```bash
curl -X POST "http://localhost:8080/api/sign" \
  -H "Content-Type: application/json" \
  -d '{
    "chain": "ethereum",
    "key_name": "master-key-01",
    "data": "0x48656c6c6f576f726c64"
  }'
```



### 响应


| 参数名称        | 类型     | 描述                  |
| --------- | ------ | ------------------- |
| chain     | string | 区块链网络名称             |
| key_name  | string | 密钥名称                |
| signature | string | 签名结果（Vault 格式）      |
| signature_hex | string | 签名结果（纯十六进制格式，适合区块链） |




### 响应示例

```json
{
    "chain": "ethereum",
    "key_name": "master-key-01",
    "signature": "vault:v1:XXXXXXXXXXXXXXXXXXXX...",
    "signature_hex": "0x3045022100915c3ea1a0081d1d1701ef94af..."
}
```



### 错误码


| HTTP 状态码 | 错误信息                  | 说明          |
| -------- | --------------------- | ----------- |
| 400      | Invalid request       | 请求参数缺失或格式错误 |
| 400      | invalid hex data      | hex 数据格式错误  |
| 500      | Internal Server Error | 服务器内部错误     |


---



## 6. 验证签名

验证签名的有效性。

### 请求

```http
POST /api/verify
Content-Type: application/json
```



### 请求参数


| 参数名称      | 类型     | 必选  | 描述               |
| --------- | ------ | --- | ---------------- |
| chain     | string | 是   | 区块链网络名称（如 `ethereum`） |
| key_name  | string | 是   | 密钥名称             |
| data      | string | 是   | 原始数据（hex 编码）     |
| signature | string | 是   | 要验证的签名           |




### 请求示例

```bash
curl -X POST "http://localhost:8080/api/verify" \
  -H "Content-Type: application/json" \
  -d '{
    "chain": "ethereum",
    "key_name": "master-key-01",
    "data": "0x48656c6c6f576f726c64",
    "signature": "vault:v1:XXXXXXXXXXXXXXXXXXXX..."
  }'
```



### 响应


| 参数名称     | 类型      | 描述      |
| -------- | ------- | ------- |
| chain    | string  | 区块链网络名称 |
| key_name | string  | 密钥名称    |
| valid    | boolean | 签名是否有效  |




### 响应示例

```json
{
    "chain": "ethereum",
    "key_name": "master-key-01",
    "valid": true
}
```



### 错误码


| HTTP 状态码 | 错误信息                  | 说明          |
| -------- | --------------------- | ----------- |
| 400      | Invalid request       | 请求参数缺失或格式错误 |
| 400      | invalid hex data      | hex 数据格式错误  |
| 500      | Internal Server Error | 服务器内部错误     |


---



## 公共错误码


| HTTP 状态码 | 错误码   | 描述          |
| -------- | ----- | ----------- |
| 400      | 40001 | 请求参数缺失      |
| 400      | 40002 | 请求参数格式错误    |
| 400      | 40003 | 请求参数值不合法    |
| 401      | 40101 | 认证失败        |
| 403      | 40301 | 权限不足        |
| 500      | 50001 | 服务器内部错误     |
| 500      | 50002 | Vault 服务不可用 |


---



## 请求头说明


| 请求头名称         | 必选  | 类型     | 描述                           |
| ------------- | --- | ------ | ---------------------------- |
| Content-Type  | 否   | string | 请求内容类型，默认 `application/json` |
| X-Vault-Token | 否   | string | Vault 访问令牌（预留字段）             |


---



## 使用示例



### 使用 Node.js

```javascript
const axios = require('axios');

// 创建密钥
async function createKey(chain, name, keyType, derived = false) {
    const response = await axios.post('http://localhost:8080/api/keys', {
        chain,
        name,
        type: keyType,
        derived
    });
    return response.data;
}

// 获取密钥列表
async function listKeys(chain) {
    const response = await axios.get('http://localhost:8080/api/keys', {
        params: { chain }
    });
    return response.data;
}

// 获取密钥详情
async function readKey(chain, keyName) {
    const response = await axios.get(`http://localhost:8080/api/keys/${keyName}`, {
        params: { chain }
    });
    return response.data;
}

// 交易签名
async function signMessage(chain, keyName, data) {
    const response = await axios.post('http://localhost:8080/api/sign', {
        chain,
        key_name: keyName,
        data
    });
    return response.data;
}

// 验证签名
async function verifySignature(chain, keyName, data, signature) {
    const response = await axios.post('http://localhost:8080/api/verify', {
        chain,
        key_name: keyName,
        data,
        signature
    });
    return response.data;
}

// 健康检查
async function healthCheck() {
    const response = await axios.get('http://localhost:8080/health');
    return response.data;
}
```



### 使用 Python

```python
import requests

# 创建密钥
def create_key(chain: str, name: str, key_type: str, derived: bool = False):
    response = requests.post(
        'http://localhost:8080/api/keys',
        json={'chain': chain, 'name': name, 'type': key_type, 'derived': derived}
    )
    return response.json()

# 获取密钥列表
def list_keys(chain: str):
    response = requests.get(
        'http://localhost:8080/api/keys',
        params={'chain': chain}
    )
    return response.json()

# 获取密钥详情
def read_key(chain: str, key_name: str):
    response = requests.get(
        f'http://localhost:8080/api/keys/{key_name}',
        params={'chain': chain}
    )
    return response.json()

# 交易签名
def sign_message(chain: str, key_name: str, data: str):
    response = requests.post(
        'http://localhost:8080/api/sign',
        json={'chain': chain, 'key_name': key_name, 'data': data}
    )
    return response.json()

# 验证签名
def verify_signature(chain: str, key_name: str, data: str, signature: str):
    response = requests.post(
        'http://localhost:8080/api/verify',
        json={'chain': chain, 'key_name': key_name, 'data': data, 'signature': signature}
    )
    return response.json()

# 健康检查
def health_check():
    response = requests.get('http://localhost:8080/health')
    return response.json()
```

---


## 7. gRPC 接口

### 7.1 gRPC 概述

gRPC 接口与 HTTP 接口功能完全一致，提供高性能的远程过程调用。

**gRPC 地址**：`{host}:{port}`

**默认端口**：50051

**Proto 文件**：`grpc/chain.proto`

### 7.2 gRPC 服务定义

```protobuf
service ChainService {
  rpc HealthCheck(HealthCheckRequest) returns (HealthCheckResponse);
  rpc CreateMasterKey(CreateMasterKeyRequest) returns (CreateMasterKeyResponse);
  rpc ListKeys(ListKeysRequest) returns (ListKeysResponse);
  rpc ReadKey(ReadKeyRequest) returns (ReadKeyResponse);
  rpc Sign(SignRequest) returns (SignResponse);
  rpc Verify(VerifyRequest) returns (VerifyResponse);
}
```

### 7.3 接口说明

#### 7.3.1 健康检查

```protobuf
message HealthCheckRequest {}
message HealthCheckResponse { string status = 1; }
```

#### 7.3.2 创建主密钥

```protobuf
message CreateMasterKeyRequest {
  string chain = 1;
  string name = 2;
  string type = 3;
  bool derived = 4;
}
message CreateMasterKeyResponse {
  string message = 1;
  string chain = 2;
  string name = 3;
  string type = 4;
  bool derived = 5;
  string public_key = 6; // 公钥（PEM 格式）
}
```

#### 7.3.3 获取密钥列表

```protobuf
message ListKeysRequest { string chain = 1; }
message ListKeysResponse { repeated string keys = 1; }
```

#### 7.3.4 获取密钥详情

```protobuf
message ReadKeyRequest {
  string chain = 1;
  string key_name = 2;
}
message ReadKeyResponse {
  string request_id = 1;
  int64 version = 2;
  string name = 3;
  string creation_time = 4;
  map<string, string> keys = 5;
  int64 min_version = 6;
  int64 latest_version = 7;
}
```

#### 7.3.5 交易签名

```protobuf
message SignRequest {
  string chain = 1;
  string key_name = 2;
  string data = 3;
}
message SignResponse {
  string chain = 1;
  string key_name = 2;
  string signature = 3;
  string signature_hex = 4;
}
```

#### 7.3.6 验证签名

```protobuf
message VerifyRequest {
  string chain = 1;
  string key_name = 2;
  string data = 3;
  string signature = 4;
}
message VerifyResponse {
  string chain = 1;
  string key_name = 2;
  bool valid = 3;
}
```

### 7.4 客户端调用示例

#### Go 客户端

```go
import "github.com/koku-web3/coordinator/grpc"

func main() {
    client, err := grpc.NewClient("localhost:50051")
    if err != nil {
        panic(err)
    }
    defer client.Close()

    ctx := context.Background()

    // 创建密钥
    resp, err := client.CreateMasterKey(ctx, "ethereum", "my-key", "ecdsa-p256", false)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Created: %s\n", resp.Message)

    // 签名
    signResp, err := client.Sign(ctx, "ethereum", "my-key", "0x48656c6c6f")
    if err != nil {
        panic(err)
    }
    fmt.Printf("Signature: %s\n", signResp.SignatureHex)
}
```

#### grpcurl 工具调用

```bash
# 健康检查
grpcurl -plaintext localhost:50051 chain.ChainService/HealthCheck

# 创建密钥
grpcurl -plaintext -d '{"chain":"ethereum","name":"test-key","type":"ecdsa-p256","derived":false}' \
  localhost:50051 chain.ChainService/CreateMasterKey

# 获取密钥列表
grpcurl -plaintext -d '{"chain":"ethereum"}' \
  localhost:50051 chain.ChainService/ListKeys

# 签名
grpcurl -plaintext -d '{"chain":"ethereum","key_name":"test-key","data":"0x48656c6c6f576f726c64"}' \
  localhost:50051 chain.ChainService/Sign
```

---

## 更新日志

| 版本 | 日期 | 描述 |
| ------ | ---------- | ---------------------------- |
| v1.0.1 | 2026-07-28 | 初始版本 |
| v1.0.2 | 2026-07-28 | 新增签名和验签 API |
| v1.0.3 | 2026-07-28 | 创建密钥 API 新增 `type` 和 `derived` 参数 |
| v1.0.4 | 2026-07-28 | 签名 API 返回值新增 `signature_hex` 字段 |
| v1.0.5 | 2026-08-02 | 新增 gRPC 接口支持 |
| v1.0.6 | 2026-08-05 | 创建密钥 API 返回值新增 `public_key` 字段 |
