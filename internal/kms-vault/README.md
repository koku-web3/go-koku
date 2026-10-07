# HashiCorp Vault 部署与配置

## Vault 介绍

HashiCorp Vault 是一款用于安全管理敏感数据（如密钥、令牌、证书）的工具，支持加密、访问控制及动态凭证。在本项目中，Vault 作为去中心化密钥管理系统，通过 Transit Engine 为区块链交易提供密钥生成、加密和签名能力，并与 AWS IAM 集成实现安全认证，是链服务安全核心组件。

## 单机部署说明

- docker compose 一台机器启动 3 个 Vault 节点
- 使用 AWS IAM User 让 Vault 的 `AWS Auth Method` 与 AWS 建立信任
- Vault 生成的密钥数据保存在宿主机
- 使用 Key Share 的方式进行解封（unseal）
- 解封要求 2/3 ，生成三把密钥碎片，收集任意2把就能解封

## 依赖

需要先安装以下软件：

- docker
- openSSL
- base64
- gpg
- jq

## 1、需要准备的文件

>**提示：如果用与开发环境快速启动可直接使用**`./vault-deploy`**目录下的文件，无需生成，可直接跳过本节。**

### 1.1 TLS证书文件

保存路径`./vault-deploy/local-config/certs`

证书文件用于 Vault 节点之间安全通信，开发部署三个节点可以使用同一份证书。

执行脚本生成所需证书：

```bash
sh ../../scripts/gen-certs.sh

# 最终目录
# certs/
# ├── ca.pem
# ├── vault.key
# └── vault.pem   
```



### 1.2 公钥文件

由于解封使用 Key Share 的方式，所以在 Vault 初始化时默认会在控制台直接输出每一把主密钥碎片的明文。我们希望 Vault 使用提供的公钥文件，对密钥碎片加密，这样就能很好的对碎片进行保密。

因为我们使用 2/3 规则，所以需要生成 3 个公钥文件对应 3 把密钥碎片，由企业不同角色持有（如公司负责人、项目负责人、运营负责人各一把），需要任意两把密钥碎片才能启动 Vault 服务。

执行以下命令生成 3 个公钥文件，外加一个 root.token 公钥文件。保存到路径`./vault-deploy/local-config/encryption`。

```bash
# 生成 admin1 公钥
gpg --full-generate-key
gpg --export admin1@xxx.com > admin1_public.gpg
...
gpg --full-generate-key
gpg --export admin1@xxx.com > root_public.gpg

# 最终目录
# encryption/
# ├── admin1_public.gpg
# ├── admin2_public.gpg
# ├── admin3_public.gpg
# └── root_public.gpg
```



### 1.3 Vault 配置文件

每个节点对应一个配置文件。保存到路径`./vault-deploy/local-config/hcl`。

```bash
# 最终目录
# hcl/
# ├── vault-1.hcl
# ├── vault-2.hcl
# └── vault-3.hcl
```



### 1.4 策略文件

用于后面配置角色（服务）对 Transit（引擎）的访问权限。保存到路径`./vault-deploy/local-config/policy`。

```bash
# 最终目录
# policy/
# ├── keycreator.hcl
# └── signer.hcl
```



## 2、需要准备的配置



### 2.1 AWS IAM Role & User

按照 [Vault接入AWS身份认证](../../docs/aws-iam-auth.md) 的步骤获得以下4个关键信息：

- `access_key`
- `secret_key`
- 角色 `create-key-role` 的ARN
- 角色 `signer-role` 的ARN



## 3、部署
执行填入 AWS IAM 关键配置信息

```bash
export AWS_ACCESS_KEY="" # <3.1 获得的 access_key>
export AWS_SECRET_KEY="" # <3.1 获得的 secret_key>
export ARN_CREATE_KEY="" # <3.1 获得的 create-key-role ARN>
export ARN_SIGN="" # <3.1 获得的 signer-role ARN>
```

### 3.1 执行部署脚本
*部署前需要准备好 [1、需要准备的文件](#1、需要准备的文件) 中所有文件*

```bash
sh deploy.sh
```

### 3.2 执行解封(unseal)脚本
> 仅限开发环境
```bash
sh unseal.sh
```

## 4、实际应用
### 4.1 transit 引擎的划分

项目按功能划分出3个transit引擎，主要使用的密钥类型是 `aes256-gcm96`，GCM模式的AES对称加密，96为随机数。

格式：`transit/{transit_name}/{key_name}`

- `transit/core/{chainCode}-seed` **负责核心主密钥种子：** 一个区块链对应一个随机种子，遵循BIP-44规则派生；使用该种子可以派生出该链下所有的子密钥。
- `transit/operations/{chainCode}-privkey` **负责运营密钥：** 包括财务密钥、归集地址密钥、手续费地址密钥等；使用此引擎下派生的密钥进行加解密。
- `transit/user/{chainCode}-privkey` **负责用户密钥** 用户充值、提现地址密钥；使用此引擎下派生的密钥进行加解密。

其中：

- {transit_name}：core、operations、user
- {key_name}：{chainCode}-seed、{chainCode}-privkey、{chainCode}-privkey

**关于 Transit 的更多信息参考 [https://developer.hashicorp.com/vault/api-docs/secret/transit](https://developer.hashicorp.com/vault/api-docs/secret/transit)**