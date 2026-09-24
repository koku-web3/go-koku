# HashiCorp Vault 部署

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

## 1、需要准备的文件

**提示：如果用与开发环境快速启动可直接使用`./vault-deploy`目录下的文件，无需生成。**

### 1.1 TLS证书文件

保存路径`./vault-deploy/local-config/certs`

证书文件用于 Vault 节点之间安全通信，开发部署三个节点可以使用同一份证书。

执行脚本生成所需证书：
``` bash
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
``` bash
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
``` bash
# 最终目录
# hcl/
# ├── vault-1.hcl
# ├── vault-2.hcl
# └── vault-3.hcl
```
### 1.4 策略文件
用于后面配置角色（服务）对 Transit（引擎）的访问权限。保存到路径`./vault-deploy/local-config/policy`。
``` bash
# 最终目录
# policy/
# ├── keycreator.hcl
# └── signer.hcl
```


## 2、部署
```bash
test -d ../data/1 || mkdir -p ../data/1
test -d ../data/2 || mkdir -p ./data/2
test -d ../data/3 || mkdir -p ./data/3
chmod -R 777 ../data/{1,2,3}

test -d ../secure || mkdir -p ../secure
chmod -R 666 ../secure

# 配置文件卷（Vault 配置文件）
docker volume create vault-config

# 部署节点 1
docker compose -f vault-deploy/vault.compose.yml up vault-1 --build --detach

# 初始化节点 1
docker exec -it prod-vault-1 \
  vault operator init -key-shares=3 -key-threshold=2 -pgp-keys="/vault/encryption/admin1_public.gpg,/vault/encryption/admin2_public.gpg,/vault/encryption/admin3_public.gpg" -root-token-pgp-key="/vault/encryption/root_public.gpg" -format=json > ./secure/vault-init.json

# 解封节点 1
for i in 0 1; do
  token=$(jq -r ".unseal_keys_b64[$i]" ./secure/vault-init.json | base64 --decode | gpg -dq)
  docker exec prod-vault-1 vault operator unseal "$token"
done

# 部署节点 2、3
docker compose -f vault-deploy/vault.compose.yml up vault-2 --build --detach
docker compose -f vault-deploy/vault.compose.yml up vault-3 --build --detach

# 解封节点 2、3
for i in 0 1; do
  token=$(jq -r ".unseal_keys_b64[$i]" ./secure/vault-init.json | base64 --decode | gpg -dq)
  docker exec prod-vault-2 vault operator unseal "$token"
  docker exec prod-vault-3 vault operator unseal "$token"
done
```

验证三个节点是否已建立集群：
``` bash
token=$(jq -r '.root_token' ./secure/vault-init.json | base64 --decode | gpg -dq)
docker exec -e VAULT_TOKEN="$token" prod-vault-1 vault operator raft list-peers

# 正常时应看到 3 个节点状态如下：

Node           Address                  State       Voter
----           -------                  -----       -----
prod-vault-1   prod-vault-1:8201        leader      true
prod-vault-2   prod-vault-2:8201        follower    true
prod-vault-3   prod-vault-3:8201        follower    true

```

## 3、配置 Vault
### 3.1 AWS IAM Role & User
按照 [Vault接入AWS身份认证](../../docs/aws-iam-auth.md) 的步骤获得以下关键信息：
- `access_key`
- `secret_key`
- 角色 `create-key-role` 的ARN
- 角色 `signer-role` 的ARN

### 3.2 创建三个 transit
``` bash
AWS_ACCESS_KEY = "" # <3.1 获得的 access_key>
AWS_SECRET_KEY = "" # <3.1 获得的 secret_key>
ARN_CREATE_KEY = "" # <3.1 获得的 create-key-role ARN>
ARN_SIGN = "" # <3.1 获得的 signer-role ARN>

token=$(jq -r '.root_token' ./secure/vault-init.json | base64 --decode | gpg -dq)

# 创建三个 transit
docker exec -e VAULT_TOKEN="$token" prod-vault-1 vault secrets enable -path=transit/core transit
docker exec -e VAULT_TOKEN="$token" prod-vault-1 vault secrets enable -path=transit/operations transit
docker exec -e VAULT_TOKEN="$token" prod-vault-1 vault secrets enable -path=transit/user transit

# 写入策略文件
docker exec -e VAULT_TOKEN="$token" prod-vault-1 vault policy write keycreator /vault/config/policy/keycreator.hcl
docker exec -e VAULT_TOKEN="$token" prod-vault-1 vault policy write signer /vault/config/policy/signer.hcl

# 启用 AWS auth method
docker exec -e VAULT_TOKEN="$token" prod-vault-1 vault auth enable aws

# 配置 AWS 客户端凭证
docker exec -e VAULT_TOKEN="$token" prod-vault-1 vault write auth/aws/config/client \
    access_key="$AWS_ACCESS_KEY" \
    secret_key="$AWS_SECRET_KEY"

# 创建 Vault Role并绑定到AWS IAM Role
docker exec -e VAULT_TOKEN="$token" prod-vault-1 vault write auth/aws/role/role-key-creator \
    auth_type=iam \
    bound_iam_principal_arn=$ARN_CREATE_KEY \
    policies=keycreator

docker exec -e VAULT_TOKEN="$token" prod-vault-1 vault write auth/aws/role/role-signer \
    auth_type=iam \
    bound_iam_principal_arn=$ARN_SIGN \
    policies=signer

```

验证是否生效：
```bash
token=$(jq -r '.root_token' ./secure/vault-init.json | base64 --decode | gpg -dq)
docker exec -e VAULT_TOKEN="$token" prod-vault-1 vault read auth/aws/role/role-key-creator
docker exec -e VAULT_TOKEN="$token" prod-vault-1 vault read auth/aws/role/role-signer
```


## 4、transit 引擎划分

### 4.1 说明

项目按功能划分出3个transit引擎，主要使用的密钥类型是 `aes256-gcm96`，GCM模式的AES对称加密，96为随机数。

格式：`transit/{transit_name}/{key_name}`

- `transit/core/{chainCode}-masterkey` **负责核心密钥：** 一个区块链对应一把主密钥，遵循BIP-44规则派生；主密钥的种子（Seed）、该Seed派生的两把密钥（account为 0 和 1） 使用此引擎下派生的密钥进行加解密。
- `transit/operations/{chainCode}-privkey` **负责运营密钥：** 包括财务密钥、归集地址密钥、手续费地址密钥等；使用此引擎下派生的密钥进行加解密。
- `transit/user/{chainCode}-privkey` **负责用户密钥** 用户充值、提现地址密钥；使用此引擎下派生的密钥进行加解密。

其中：

- {transit_name}：core、operations、user
- {key_name}：{chainCode}-masterkey、{chainCode}-privkey、{chainCode}-privkey



### 4.2 示例

加密的路径格式为：`transit/{transit_name}/encrypt/{key_name}`。

以下展示 Ethereum 对**主密钥种子**进行加密

```bash
 curl --header "X-Vault-Token: hvs.g1bZWi6flTJdB5GZopREVdBU" \
     --request POST \
     --data '{
       "plaintext": "MTIzNDU2Nzg5MA==",
       "context": "ZXRoZXJldW0tdGVzdC11c2VyLTE="
     }' \
     http://127.0.0.1:8200/v1/transit/core/encrypt/masterkey
```

**关于 Transit 的更多信息参考 https://developer.hashicorp.com/vault/api-docs/secret/transit**