# HashiCorp Vault 部署

## Vault 介绍

HashiCorp Vault 是一款用于安全管理敏感数据（如密钥、令牌、证书）的工具，支持加密、访问控制及动态凭证。在本项目中，Vault 作为去中心化密钥管理系统，通过 Transit Engine 为区块链交易提供密钥生成、加密和签名能力，并与 AWS IAM 集成实现安全认证，是链服务安全核心组件。

## 1、安装

### macOS

```bash
# 添加 HashiCorp 的官方仓库
brew tap hashicorp/tap

# 安装 Vault
brew install hashicorp/tap/vault

# 安装完成后，运行以下命令查看版本：
vault --version
```

### Ubuntu / Debian 系统

```bash
# 1. 安装基础依赖与 HashiCorp GPG 密钥
sudo apt-get update && sudo apt-get install -y gpg coreutils
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg

# 2. 将 HashiCorp 官方源添加到 APT 软件源
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list

# 3. 更新源并安装 Vault
sudo apt-get update && sudo apt-get install vault
```



### CentOS / RHEL / Rocky Linux 系统

```bash
# 1. 安装 yum-utils 依赖
sudo yum install -y yum-utils

# 2. 添加 HashiCorp 官方 YUM 源
sudo yum-config-manager --add-repo https://rpm.releases.hashicorp.com/RHEL/hashicorp.repo

# 3. 安装 Vault
sudo yum -y install vault
```



### 其他 Linux 发行版

直接下载预编译二进制文件安装

```bash
# 1. 下载指定版本的压缩包（以最新稳定版为例，请根据需要替换版本号）
wget https://releases.hashicorp.com/vault/1.15.2/vault_1.15.2_linux_amd64.zip

# 2. 解压文件（若无 unzip 命令可通过 apt/yum 安装）
unzip vault_1.15.2_linux_amd64.zip

# 3. 将二进制文件移动到系统 PATH 路径下
sudo mv vault /usr/local/bin/

# 4. 给予执行权限
sudo chmod +x /usr/local/bin/vault
```



### Docker Compose 部署

1、创建 docker-compose.yml 文件

```bash
version: '3.7'
services:
  vault:
    image: hashicorp/vault:latest
    container_name: vault
    ports:
      - "8200:8200"
    environment:
      VAULT_ADDR: 'http://127.0.0.1:8200'
      VAULT_LOCAL_CONFIG: |
        storage "file" {
          path = "/vault/file"
        }
        listener "tcp" {
          address = "0.0.0.0:8200"
          tls_disable = 1
        }
        ui = true
    cap_add:
      - IPC_LOCK
    volumes:
      - ./vault/file:/vault/file
    command: server
```

2、启动容器

```bash
docker-compose up -d
```

3、验证安装

```bash
vault --version
```



## 2、启动 Vault



### 2.1 创建一个配置文件

```bash
# 1. 开启可视化 UI 界面
ui = false

# 2. 全局网络行为配置
api_addr     = "http://127.0.0.1:8200"
cluster_addr = "http://127.0.0.1:8201"
disable_mlock = true

# 3. 数据落盘存储（使用本地 Raft）
storage "raft" {
  path    = "/Users/jan/vault/data"
  node_id = "vault_node_a"
}

# 4. 网络监听（这里演示的是本地开发用的 HTTP 模式，生产请务必配证书并设置 tls_disable = "false"）
listener "tcp" {
  address         = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_disable     = "true"
}
```

命名为`vault-config.hcl`并保存

### 2.2 启动 Vault 服务

```bash
vault server -config=./vault-config.hcl
```



### 2.3 设置环境变量

设置地址变量，方便使用CLI命令

```bash
export VAULT_ADDR='http://127.0.0.1:8200'
```



## 3、生成主密钥（Master key）密钥

生成 3 把密钥碎片，并且只需要 2 把就能开锁（n of m）。

```bash
vault operator init -key-shares=3 -key-threshold=2
```



## 4、解封（unseal）

使用第3步生成的密钥碎片进行解封。如：公司负责人一把、技术负责人一把、放在保险库一把。

```bash
# 执行命令后按提示输入一把密钥，然后再执行一次命令并输入另一把密钥（2/3）
vault operator unseal
```



## 5、激活 Transit 引擎

> 提示：执行命令前请先阅读官方文档[https://developer.hashicorp.com/vault/docs/secrets/transit](https://developer.hashicorp.com/vault/docs/secrets/transit)，了解 transit 引擎相关概念。

下面以 path `transit/bitcoin` 为例：

### 5.1 激活

```bash
# 激活 transit 引擎
vault secrets enable -path=transit/bitcoin transit
```



### 5.2 查看

```bash
# 列出当前所有已激活的引擎
vault secrets list
```

```bash
# 查看指定transit引擎详情
vault read sys/mounts/transit/bitcoin
```



## 6、策略（Policy）配置

> 提示：执行命令前请先阅读官方文档[https://developer.hashicorp.com/vault/docs/commands/policy](https://developer.hashicorp.com/vault/docs/commands/policy)，了解 policy 相关概念。



### 6.1 编写策略文件

编写一个`transit/bitcoin`相关的策略：可以对它进行创建密钥、更新密钥、读取详情、读取它的所有key列表。

```bash
path "transit/bitcoin/*" {
  capabilities = ["create", "update", "read","list"]
}
```

将文件保存并命名为`bitcoin-policy.hcl`。

### 6.2 写入策略

命令： `vault policy write [策略名称] [文件路径]`

```bash
vault policy write bitcoin-policy ./bitcoin-policy.hcl
```

写入了名称为`bitcoin-policy`的策略到 vault 系统。

## 7、AWS相关配置

> 提示：继续前请先自行了解AWS IAM Role/User相关概念。

**架构简述**
`chain-ser`服务和`vault`服务分别部署在不同的AWS EC2（同一个内网）。使用 AWS IAM Role 主要作用是做身份认证：

- 在AWS先创建一个Role`vault-auth-role`并让`vault`服务绑定概角色和对应的策略。
- 在AWS创建另一个Role`chain-serv-ec2-role`绑定到 `chain-ser`的EC2，赋予它有权限扮演`vault-auth-role`角色。



### 7.1 创建角色 vault-auth-role



##### 1. 进入 IAM 服务

导航到 **AWS Console → IAM → Roles → Create role**

##### 2. 选择可信实体

- Trusted entity type: **AWS account**
- This account: **This account**
- 点击 **Next**



##### 3. 添加权限（先跳过）

- 直接点击 **Next**（稍后添加权限）



##### 4. 设置角色名称

- Role name: `vault-auth-role`
- 点击 **Create role**



### 7.2 创建角色 chain-serv-ec2-role



##### 1. 进入 IAM 服务

**IAM → Roles → Create role**

##### 2. 选择可信实体

- Trusted entity type: **AWS service**
- Use case: **EC2**
- 点击 **Next**



##### 3. 添加权限

点击 **Create policy**，新窗口中：

**JSON 标签页：**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::<你的AWS账户ID>:role/vault-auth-role"
    }
  ]
}
```

- 点击 **Next → Next**
- Policy name: `chain-serv-ec2-policy`
- 点击 **Create policy**

返回角色创建页面，勾选刚创建的 `chain-serv-ec2-policy`，点击 **Next**

##### 4. 设置角色名称

- Role name: `chain-serv-ec2-role`
- 点击 **Create role**



### 7.3 编辑“信任策略”

导航到 **AWS Console → IAM → Roles → 点击“vault-auth-role”

进入该角色的 Trust relationships → Edit trust policy，粘贴：

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<你的AWS账户ID>:role/chain-serv-ec2-role"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```



### 7.4 EC2关联 Instance Profile（实例文件）

> 注意：仅需在部署`chain-ser`的 EC2 配置，`vault`不需要。

在启动EC2实例时配置：
EC2 → 实例 → 启动新实例 → 高级详细信息 → 在“IAM 实例配置文件”项选择前面创建的`chain-serv-ec2-role` → 完成

## 8、Vault Role



## 8.1 绑定

Vault系统也有自己的角色，我们需要把 AWS IAM Role 绑定到它的角色：

```bash
curl --header "X-Vault-Token: <root_token>" \
     --request POST \
     --data '{"role": "bitcoin-client", "arn": "arn:aws:iam::<你的AWS账户ID>:role/vault-auth-role", "policies": ["bitcoin-policy"]}' \
     http://127.0.0.1:8200/v1/auth/aws/role/bitcoin-client
```

其中`arn`对应的就是AWS角色`vault-auth-role`的ARN。

## 8.2 验证

执行命令`vault read auth/aws/role/bitcoin-client` 查看是否已绑定成功。

## 9、提供服务

启动`chain-serv`调用该服务，`chain-serv`接口文档[https://github.com/Koku-Web3/chain-serv](https://github.com/Koku-Web3/chain-ser)。