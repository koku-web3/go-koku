# Docker compose 部署

### 0. 创建 volume 保存文件 + 创建 Raft 数据目录

```bash
# 配置文件卷（TLS 证书、加密密钥等）
docker volume create vault-config

# Raft 数据目录（每个节点一份，必须分别创建）
# 容器内运行 Vault 的主进程使用 UID=100（即 vault 用户），因此宿主机的 Raft 数据目录需要赋予该用户写权限
test -d ./data/1 || mkdir -p ./data/1
test -d ./data/2 || mkdir -p ./data/2
test -d ./data/3 || mkdir -p ./data/3
chmod -R 777 ./data/{1,2,3}
```

> **为什么用 bind mount 而不是命名 volume？**
>
> - 数据位置明确 (`internal/kms-vault/data/N`), 便于备份脚本、监控、跨机器迁移
> - 配合 `rsync` / `tar` 备份比 `docker volume` 更直观
> - 上 k8s 时可直接对应到 `hostPath` / `PVC`, 路径不变
> - 已经在 `.gitignore` 中忽略, 不会污染 git

### 1. 先只启动第一个节点（用它来做集群初始化）

```bash
docker compose -f vault-deploy/vault.compose.yml up vault-1 --build --detach
```

`--build`

- 在启动容器之前，强制重新构建镜像（即使镜像已经存在）
- 相当于先执行 `docker compose build`，再执行 `up`
- 常用场景：你修改了 Dockerfile 或代码，需要让改动生效，而不是用旧的缓存镜像

`--detach`**（简写** `-d`**）**

- 让容器在**后台**运行（detached mode，分离模式）
- 不加这个参数时，容器会在前台运行，日志直接打印在你的终端里，且终端会被占用（Ctrl+C 会停止容器）
- 加了 `-d` 之后，命令执行完就会立刻返回，容器继续在后台运行，你可以继续用这个终端做别的事

**整条命令的意思：**

- `-f vault-deploy/vault.compose.yml`：指定使用这个 compose 文件（而不是默认的 `docker-compose.yml`）
- `up vault-1`：只启动（并在需要时创建）名为 `vault-1` 的服务，而不是文件里定义的所有服务
- `--build`：启动前重新构建该服务的镜像
- `--detach`：以后台方式运行



### 2. 对该节点执行初始化，生成 root token 和 unseal keys（务必保存到安全位置！）

```bash
docker exec -it prod-vault-1 \
  vault operator init -key-shares=3 -key-threshold=2 -pgp-keys="/vault/encryption/admin1_public.gpg,/vault/encryption/admin2_public.gpg,/vault/encryption/admin3_public.gpg" -root-token-pgp-key="/vault/encryption/root_public.gpg" -format=json > ./secure/vault-init.json
```

结果会输出在 `vault-init.json`文件，内容大致如下：

```json
{
  "unseal_keys_b64": [
    "wcFMA...lTxB3wU=", // admin1公钥加密的数据 base64 格式
    "wcFMA...QxQc=",  // admin2公钥加密的数据 base64 格式
    "wcFMA9...csOJ8w="  // admin3公钥加密的数据 base64 格式
  ],
  "unseal_keys_hex": [
    "c1c14...1df05", // admin1公钥加密的数据 十六进制 格式
    "c1c14...0c507", // admin2公钥加密的数据 十六进制 格式
    "c1c14...e27cc"  // admin3公钥加密的数据 十六进制 格式
  ],
  "unseal_shares": 3,
  "unseal_threshold": 2,
  "recovery_keys_b64": [],
  "recovery_keys_hex": [],
  "recovery_keys_shares": 0,
  "recovery_keys_threshold": 0,
  "root_token": "wcFMA7UwY...Ly1NL7"  // root token base64 格式
}
```



### 3. unseal（解封）节点1

用生成的 unseal key（本配置为 3 把碎片、阈值 2，任意 2 把即可）对节点 1 解封，每一个节点都需要单独解封。

**注意:** 正确的解封做法应该是每把主密钥碎片的持有人，在一台绝对安全的机器安装好 GPG 工具，生成上面的 admin_public.gpg 公钥文件，拿到`unseal_keys_b64`后，在本机使用 GPG 工具解密。然后安装 vault CLI 工具，执行`export VAULT_ADDR=https://<vault-1-host>:8200`，再执行`vault operator unseal <解密后的碎片>`。这样就保证了密钥不会明文出现在其他地方。

```bash
# admin1 本机，不要把私钥拷进容器
jq -r '.unseal_keys_b64[0]' vault-init.json \
  | base64 --decode | gpg -dq

export VAULT_ADDR=https://<vault-1-host>:8200
vault operator unseal   # 粘贴上一步输出
```

以上命令直接对得到的`vault-init.json`文件进行 base64解码，然后调取 GPG 工具再对其进行解密，输出结果类似`5f5a6de7414d824d8f5348390acf54757e18dc4d3402f70a268f8172852bca4416%`就是碎片的明文 hex 格式。

其他节点同理。

---

**如果只是本地开发所有持有人同一机器：**

`unseal_keys_b64` 里每一项都是「该管理员公钥加密后的密文」再做 base64。必须**逐把**取出、解码、用对应私钥解密，再交给 `vault operator unseal`。阈值是 2，解封任意两把即可。

```bash
for i in 0 1; do
  token=$(jq -r ".unseal_keys_b64[$i]" ./secure/vault-init.json | base64 --decode | gpg -dq)
  docker exec prod-vault-1 vault operator unseal "$token"
done
```



### 4. 检查节点 1 状态，确认 Sealed=false、HA Enabled=true

```bash
docker exec -it prod-vault-1 vault status
```

输出结果：

```bash
Key                     Value
---                     -----
Seal Type               shamir
Initialized             true
Sealed                  false  #表示已解封
Total Shares            3
Threshold               2
Version                 2.0.4
Build Date              2026-08-03T16:14:36Z
Storage Type            raft
Cluster Name            prod-vault
Cluster ID              738d9e62-3151-6318-87ab-892d5387823b
Removed From Cluster    false
HA Enabled              true
HA Cluster              https://prod-vault-1:8201
HA Mode                 active
Active Since            2026-08-31T03:28:20.088378379Z
Raft Committed Index    38
Raft Applied Index      38
```



### 5. 依次启动节点 2、节点 3，并用同一批 unseal key 分别解封

```bash
docker compose -f vault-deploy/vault.compose.yml up vault-2 --build --detach

for i in 0 1; do
  token=$(jq -r ".unseal_keys_b64[$i]" ./secure/vault-init.json | base64 --decode | gpg -dq)
  docker exec prod-vault-2 vault operator unseal "$token"
done

docker compose -f vault-deploy/vault.compose.yml up vault-3 --build --detach

for i in 0 1; do
  token=$(jq -r ".unseal_keys_b64[$i]" ./secure/vault-init.json | base64 --decode | gpg -dq)
  docker exec prod-vault-3 vault operator unseal "$token"
done
```



### 6. 查看3个节点集群情况

先看容器是否都在跑：

```bash
docker compose -f vault-deploy/vault.compose.yml ps
```

再分别看三个节点的 `vault status`。期望：`Initialized=true`、`Sealed=false`、`HA Enabled=true`；其中一个 `HA Mode=active`，另外两个为 `standby`。

```bash
docker exec -it prod-vault-1 vault status
docker exec -it prod-vault-2 vault status
docker exec -it prod-vault-3 vault status
```

查看 Raft 成员（需要 root token）。本地开发可从 `vault-init.json` 解密 root token 后查询；生产环境不要在共享机器上解密。

```bash
token=$(jq -r '.root_token' ./secure/vault-init.json | base64 --decode | gpg -dq)
docker exec -e VAULT_TOKEN="$token" prod-vault-1 vault operator raft list-peers
```

正常时应看到 3 个节点，例如：

```bash
Node           Address                  State       Voter
----           -------                  -----       -----
prod-vault-1   prod-vault-1:8201        leader      true
prod-vault-2   prod-vault-2:8201        follower    true
prod-vault-3   prod-vault-3:8201        follower    true
```

`State` 一个为 `leader`，另外两个为 `follower`；`Voter` 均为 `true`。

### 7. 初始化三个 transit

使用 Root Token 执行命令，token 只提供给这次命令执行环境，命令结束，环境变量消失。

```bash
# 初始化 core operations user 密钥引擎
token=$(jq -r '.root_token' ./secure/vault-init.json | base64 --decode | gpg -dq)
docker exec -e VAULT_TOKEN="$token" prod-vault-1 vault secrets enable -path=transit/core transit
docker exec -e VAULT_TOKEN="$token" prod-vault-1 vault secrets enable -path=transit/operations transit
docker exec -e VAULT_TOKEN="$token" prod-vault-1 vault secrets enable -path=transit/user transit
```



### 8. 新建策略文件

注意：加密、解密、轮换密钥等操作都依赖 update 能力。

> `delete`权限绝对不能给与。

策略文件已保存在`./vault-deploy/local-config/policy/`目录下。

```bash
# key creator 策略
echo 'path "transit/core/*" {
  capabilities = ["create", "update", "read"]
}

path "transit/operations/*" {
  capabilities = ["create", "update", "read"]
}

path "transit/user/*" {
  capabilities = ["create", "update", "read"]
}
' 

# signer 策略
echo 'path "transit/core/*" {
  capabilities = ["update", "read", "list"]
}

path "transit/operations/*" {
  capabilities = ["update", "read", "list"]
}

path "transit/user/*" {
  capabilities = ["update", "read", "list"]
}
' 
```



### 9. 写入策略

```bash
token=$(jq -r '.root_token' ./secure/vault-init.json | base64 --decode | gpg -dq)
docker exec -e VAULT_TOKEN="$token" prod-vault-1 vault policy write keycreator /vault/config/policy/keycreator.hcl
docker exec -e VAULT_TOKEN="$token" prod-vault-1 vault policy write signer /vault/config/policy/signer.hcl
```

查看已写入策略

```bash
token=$(jq -r '.root_token' ./secure/vault-init.json | base64 --decode | gpg -dq)
docker exec -e VAULT_TOKEN="$token" prod-vault-1 vault policy list
```



### 10. 启用 AWS auth method

```bash
token=$(jq -r '.root_token' ./secure/vault-init.json | base64 --decode | gpg -dq)
docker exec -e VAULT_TOKEN="$token" prod-vault-1 vault auth enable aws
```

验证是否生效：执行以下命令，看到列表`Path`存在`aws`

```bash
token=$(jq -r '.root_token' ./secure/vault-init.json | base64 --decode | gpg -dq)
docker exec -e VAULT_TOKEN="$token" prod-vault-1 vault auth list
```



### 10. 配置 AWS 客户端凭证

`access_key`和`secret_key`用于让 Vault 的 AWS Auth Method 与 AWS 建立信任。这一步与`keycreator`和`signer`权限无关，只是为了能与 AWS 信任通信做准备。

```bash
token=$(jq -r '.root_token' ./secure/vault-init.json | base64 --decode | gpg -dq)
docker exec -e VAULT_TOKEN="$token" prod-vault-1 vault write auth/aws/config/client \
    access_key="AKIAU2CJR6GVAPIBXG7C" \
    secret_key="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"
```

```bash
# 设置 STS 端点，在于 AWS 进行验证时指定区域和地址
token=$(jq -r '.root_token' ./secure/vault-init.json | base64 --decode | gpg -dq)
docker exec -e VAULT_TOKEN="$token" prod-vault-1 vault write auth/aws/config/client \
    sts_region="us-east-1" \
    sts_endpoint="https://sts.us-east-1.amazonaws.com"
```

验证是否生效：

```bash
token=$(jq -r '.root_token' ./secure/vault-init.json | base64 --decode | gpg -dq)
docker exec -e VAULT_TOKEN="$token" prod-vault-1 vault read auth/aws/config/client
```



### 11. 创建 Vault Role并绑定到AWS IAM Role

这一步才是配置`keycreator`和`signer`的权限。

```bash
# 创建 Vault Role (role-key-creator) 并绑定到AWS IAM Role（vault@create-key-role）同时赋予`keycreator`策略
token=$(jq -r '.root_token' ./secure/vault-init.json | base64 --decode | gpg -dq)
docker exec -e VAULT_TOKEN="$token" prod-vault-1 vault write auth/aws/role/role-key-creator \
    auth_type=iam \
    bound_iam_principal_arn=arn:aws:iam::330866749866:role/vault@create-key-role \
    policies=keycreator

# 创建 Vault Role (role-signer) 并绑定到AWS IAM Role（vault@signer-role）同时赋予`keycreator`策略
token=$(jq -r '.root_token' ./secure/vault-init.json | base64 --decode | gpg -dq)
docker exec -e VAULT_TOKEN="$token" prod-vault-1 vault write auth/aws/role/role-signer \
    auth_type=iam \
    bound_iam_principal_arn=arn:aws:iam::330866749866:role/vault@signer-role \
    policies=signer

# 多个策略','分隔 policies=policy1,policy2,...
```

验证是否生效

```bash
token=$(jq -r '.root_token' ./secure/vault-init.json | base64 --decode | gpg -dq)
docker exec -e VAULT_TOKEN="$token" prod-vault-1 vault read auth/aws/role/role-key-creator

token=$(jq -r '.root_token' ./secure/vault-init.json | base64 --decode | gpg -dq)
docker exec -e VAULT_TOKEN="$token" prod-vault-1 vault read auth/aws/role/role-signer
```



### 12. 关闭宿主机 SWAP

> **为什么必须关闭宿主机 swap？**

Vault 使用 `mlock()` 系统调用锁定内存，防止敏感数据（如 unseal key、root token、Transit 解密明文）被换出到 swap。**但是本项目使用的是集成存储（Raft + BoltDB），因此** `vault-N.hcl` **中设置了** `disable_mlock = true`（这也是 HashiCorp 官方对集成存储场景的**明确推荐**，因为 BoltDB 的内存映射文件与 `mlock` 冲突，开启 mlock 会导致整个数据集被强制加载到物理内存，容易触发 OOM）。

`disable_mlock = true` 意味着 Vault **放弃了内存锁定**，此时如果宿主机 swap 开启，内核在内存压力下会**主动把 Vault 进程内存页换出到 swap 磁盘**。攻击者如果拿到宿主机 root 权限（或通过容器逃逸拿到宿主机访问权限），就可以通过读取 swap 文件/分区，恢复出可能包含密钥明文的内存数据。

关闭宿主机 swap 后，内核**无处可换出**，从根本上消除了这条密钥泄露路径。这是 HashiCorp 官方文档要求的"disable_mlock 的安全底线"：

> Disabling `mlock` is not recommended unless the systems running Vault only use **encrypted swap** or **do not use swap at all**.

**操作步骤：**

```bash
# 1. 查看当前 swap 状态
swapon -s

# 2. 临时关闭所有 swap（立即生效，重启后失效）
sudo swapoff -a

# 3. 永久关闭：编辑 /etc/fstab，注释掉所有包含 "swap" 的行
sudo vim /etc/fstab
# 例如注释掉类似这样的行：
# /dev/mapper/centos-swap none swap sw 0 0
# UUID=xxxx-xxxx-xxxx none swap sw 0 0

# 4. 重启后再用 swapon -s 验证
swapon -s
# 期望输出为空（或只有 Filename/Type/Size/Used/Prio 标题行，无实际设备）
```

**为什么不能写到 Dockerfile 里？**

`swapoff -a` 是**内核级别的系统调用**，影响的是宿主机整个 Linux 内核的 swap 状态，而不是容器内部。容器内的进程（包括 root 进程）**没有权限**操作宿主机的 swap 配置——除非以 `--privileged` 运行，但那样会让整个宿主机的 swap 被容器关闭，影响宿主机上所有其他进程，是严重的运维灾难。

所以这一项属于**宿主机运维操作**，不属于容器镜像构建范畴。