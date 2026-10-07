#!/bin/bash
# HashiCorp Vault 部署与初始化脚本
# 前置条件: 已按 README 完成证书、公钥、配置文件、策略文件准备

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="$SCRIPT_DIR/data"
SECURE_DIR="$SCRIPT_DIR/secure"
DEPLOY_DIR="$SCRIPT_DIR/vault-deploy"

# ====================== 检查依赖 ======================
MISSING=""
if ! command -v docker >/dev/null 2>&1; then
    echo "✗ docker 未安装"
    MISSING="${MISSING} docker"
else
    echo "✓ docker"
fi
if ! command -v openssl >/dev/null 2>&1; then
    echo "✗ openssl 未安装"
    MISSING="${MISSING} openssl"
else
    echo "✓ openssl"
fi
if ! command -v base64 >/dev/null 2>&1; then
    echo "✗ base64 未安装"
    MISSING="${MISSING} base64"
else
    echo "✓ base64"
fi
if ! command -v gpg >/dev/null 2>&1; then
    echo "✗ gpg 未安装 https://gnu.org/licenses/gpl.html"
    MISSING="${MISSING} gpg"
else
    echo "✓ gpg"
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "✗ jq 未安装 https://jqlang.github.io/jq"
    MISSING="${MISSING} jq"
else
    echo "✓ jq"
fi
if [ -n "${MISSING}" ]; then
    echo ""
    echo "请安装缺失的依赖后重试"
    exit 1
fi
echo ""
echo "所有依赖已安装 ✓"


echo "==> 校验 AWS IAM 环境变量"
for var in AWS_ACCESS_KEY AWS_SECRET_KEY ARN_CREATE_KEY ARN_SIGN; do
  if [ -z "$(eval echo \$$var)" ]; then
    echo "错误: $var 未设置" >&2
    echo "详情请查看 README.md 文件 2.1 节" >&2
    exit 1
  fi
done

# ====================== 检查 data 目录 ======================
echo "==> 准备数据目录"
if test -d $DATA_DIR/1; then
    echo "错误: 目录 $DATA_DIR/1 已存在" >&2
    exit 1
fi

if test -d $DATA_DIR/2; then
    echo "错误: 目录 $DATA_DIR/2 已存在" >&2
    exit 1
fi

if test -d $DATA_DIR/3; then
    echo "错误: 目录 $DATA_DIR/3 已存在" >&2
    exit 1
fi

# ====================== 检查 vault-deploy 目录 ======================
if ! test -d "$DEPLOY_DIR"; then
    echo "错误: $DEPLOY_DIR 不存在" >&2
    exit 1
fi

# ====================== 创建 data 目录 ======================
mkdir -p $DATA_DIR/1
mkdir -p $DATA_DIR/2
mkdir -p $DATA_DIR/3
chmod -R 777 $DATA_DIR/{1,2,3}

# ====================== 检查 secure 目录 ======================
test -d $SECURE_DIR || mkdir -p $SECURE_DIR
chmod 777 $SECURE_DIR
find $SECURE_DIR -type f -exec chmod 666 {} \;


# ====================== 部署 ======================

echo "==> 部署节点 1 并等待 healthy 状态"
docker compose -f $DEPLOY_DIR/vault.compose.yml up vault-1 --build --wait --detach

echo "==> 正在初始化节点1..."
docker exec -it kms-vault-1 \
  vault operator init -key-shares=3 -key-threshold=2 -pgp-keys="/vault/encryption/admin1_public.gpg,/vault/encryption/admin2_public.gpg,/vault/encryption/admin3_public.gpg" -root-token-pgp-key="/vault/encryption/root_public.gpg" -format=json > $SECURE_DIR/vault-init.json

echo "==> 解封节点 1"
for i in 0 1; do
  ti=$(jq -r ".unseal_keys_b64[$i]" $SECURE_DIR/vault-init.json | base64 --decode | gpg -dq)
  docker exec kms-vault-1 vault operator unseal "$ti"
done

echo "==> 部署节点 2、3"
docker compose -f $DEPLOY_DIR/vault.compose.yml up vault-2 --build --wait --detach
docker compose -f $DEPLOY_DIR/vault.compose.yml up vault-3 --build --wait --detach

echo "==> 解封节点 2、3"
for i in 0 1; do
  ti=$(jq -r ".unseal_keys_b64[$i]" $SECURE_DIR/vault-init.json | base64 --decode | gpg -dq)
  docker exec kms-vault-2 vault operator unseal "$ti"
  docker exec kms-vault-3 vault operator unseal "$ti"
done

echo "==> 验证三个节点是否已建立集群 (轮询直至 leader 就绪)"
token=$(jq -r '.root_token' $SECURE_DIR/vault-init.json | base64 --decode | gpg -dq)

# 集群 join 是异步的，节点 2/3 启动并解封后，
# Raft 需要几秒选举/同步 leader。这里最多等 60 秒。
MAX_WAIT=60
elapsed=0
cluster_ok=0

while [ "$elapsed" -lt "$MAX_WAIT" ]; do
  output=$(docker exec -e VAULT_TOKEN="$token" kms-vault-1 vault operator raft list-peers 2>&1) || {
    echo "  raft list-peers 执行失败, 继续重试..." >&2
    sleep 2; elapsed=$((elapsed + 2)); continue
  }
  echo "$output"

  # 必须同时包含 3 个节点，且每个节点的 Voter 都为 true、vault-1 是 leader
  if echo "$output" | grep -q "kms-vault-1" \
     && echo "$output" | grep -q "kms-vault-2" \
     && echo "$output" | grep -q "kms-vault-3" \
     && echo "$output" | grep -A1 "^kms-vault-1" | grep -q "leader" \
     && echo "$output" | grep -A1 "^kms-vault-1" | grep -q "true" \
     && echo "$output" | grep -A1 "^kms-vault-2" | grep -q "true" \
     && echo "$output" | grep -A1 "^kms-vault-3" | grep -q "true"; then
    cluster_ok=1
    break
  fi

  echo "  vault集群尚未就绪, 等待...(2 秒后自动重试)" >&2
  sleep 2
  elapsed=$((elapsed + 2))
done

if [ "$cluster_ok" -ne 1 ]; then
  echo "错误: ${MAX_WAIT}s 内集群未建立成功 (未找到 3 个 Voter=true 节点, 或 vault-1 未成为 leader)" >&2
  exit 1
fi
echo "==> 集群建立成功 (3 个节点均为 Voter=true, vault-1 为 leader)"

# ====================== 配置 Vault ======================

token=$(jq -r '.root_token' $SECURE_DIR/vault-init.json | base64 --decode | gpg -dq)

echo "==> 创建三个 transit"
docker exec -e VAULT_TOKEN="$token" kms-vault-1 vault secrets enable -path=transit/core transit
docker exec -e VAULT_TOKEN="$token" kms-vault-1 vault secrets enable -path=transit/operations transit
docker exec -e VAULT_TOKEN="$token" kms-vault-1 vault secrets enable -path=transit/user transit

echo "==> 写入策略文件"
docker exec -e VAULT_TOKEN="$token" kms-vault-1 vault policy write keycreator /vault/config/policy/keycreator.hcl
docker exec -e VAULT_TOKEN="$token" kms-vault-1 vault policy write signer /vault/config/policy/signer.hcl

echo "==> 启用 AWS auth method"
docker exec -e VAULT_TOKEN="$token" kms-vault-1 vault auth enable aws

echo "==> 配置 AWS 客户端凭证"
docker exec -e VAULT_TOKEN="$token" kms-vault-1 vault write auth/aws/config/client \
    access_key="$AWS_ACCESS_KEY" \
    secret_key="$AWS_SECRET_KEY"

echo "==> 创建 Vault Role 并绑定到 AWS IAM Role"
docker exec -e VAULT_TOKEN="$token" kms-vault-1 vault write auth/aws/role/role-key-creator \
    auth_type=iam \
    bound_iam_principal_arn=$ARN_CREATE_KEY \
    policies=keycreator

docker exec -e VAULT_TOKEN="$token" kms-vault-1 vault write auth/aws/role/role-signer \
    auth_type=iam \
    bound_iam_principal_arn=$ARN_SIGN \
    policies=signer

echo "==> 验证是否生效"
docker exec -e VAULT_TOKEN="$token" kms-vault-1 vault read auth/aws/role/role-key-creator
docker exec -e VAULT_TOKEN="$token" kms-vault-1 vault read auth/aws/role/role-signer

echo "==> 部署与配置完成, 3个 vault 节点已启动成功"