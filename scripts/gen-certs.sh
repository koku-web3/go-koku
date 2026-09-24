#!/bin/bash
#
# gen-certs.sh - 生成 mTLS 所需的证书
# 用法: ./scripts/gen-certs.sh [--dev]
#   --dev    生成开发/测试用证书（CN 固定，不校验 SAN）
#
# 产物目录结构:
#   certs/
#   ├── ca/
#   │   └── ca.pem                    # 自签 CA（所有节点共享）
#   ├── server/
#   │   ├── keycreator.pem/.key      # key-creator 服务端证书,同时作为客户端的证书
#   │   ├── signer.pem/.key          # signer 服务端证书,同时作为客户端的证书
#   │   └── coordinator.pem/.key      # coordinator 服务端证书,同时作为客户端的证书
#   internal/
#   ├── kms-vault/vault-deploy/local-config/certs/
#   │                                       ├── ca.pem     # 从 certs/ca 拷贝
#   │                                       ├── vault.key  # Vault 节点间通信 服务端证书对应的私钥
#   │                                       ├── vault.pem  # Vault 节点间通信 服务端证书

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CERTS_DIR="$ROOT_DIR/certs"
OUT_DIR="${OUT_DIR:-$CERTS_DIR}"

mkdir -p "$OUT_DIR/ca" "$OUT_DIR/server"

# 生成参数
DAYS=3650          # 10年有效期
CA_SUBJECT="/CN=go-koku-mtls-ca"
SERVER_NAMES=(
    "key-creator"
    "signer"
    "coordinator"
)

echo "=== 生成 CA ==="
openssl genrsa -out "$OUT_DIR/ca/ca.key" 4096 2>/dev/null
openssl req -x509 -new -nodes -key "$OUT_DIR/ca/ca.key" \
    -sha256 -days $DAYS \
    -subj "$CA_SUBJECT" \
    -out "$OUT_DIR/ca/ca.pem" 2>/dev/null
echo "  CA: $OUT_DIR/ca/ca.pem"

# ========== 生成 Vault mTLS 证书 ==========
echo ""
echo "=== 生成 Vault mTLS 证书 ==="
VAULT_CERTS_DIR="$ROOT_DIR/internal/kms-vault/vault-deploy/local-config/certs"
mkdir -p "$VAULT_CERTS_DIR"
VAULT_KEY="$VAULT_CERTS_DIR/vault.key"
VAULT_CSR=$(mktemp)
VAULT_PEM="$VAULT_CERTS_DIR/vault.pem"

echo "  生成 Vault 私钥..."
openssl genrsa -out "$VAULT_KEY" 4096 2>/dev/null

echo "  生成 Vault CSR..."
openssl req -new -key "$VAULT_KEY" \
    -subj "/CN=prod-vault" \
    -out "$VAULT_CSR" 2>/dev/null

echo "  使用 CA 签发 Vault 证书..."
VAULT_EXT=$(mktemp)
printf "subjectAltName=DNS:prod-vault-1,DNS:prod-vault-2,DNS:prod-vault-3,IP:127.0.0.1" > "$VAULT_EXT"
openssl x509 \
    -req \
    -in "$VAULT_CSR" \
    -CA "$OUT_DIR/ca/ca.pem" \
    -CAkey "$OUT_DIR/ca/ca.key" \
    -CAcreateserial \
    -out "$VAULT_PEM" \
    -days 1825 \
    -sha256 \
    -extfile "$VAULT_EXT" 2>/dev/null
rm -f "$VAULT_EXT"

rm -f "$VAULT_CSR"
chmod 600 "$VAULT_KEY"

# 复制 CA 证书到 Vault 部署目录
cp "$OUT_DIR/ca/ca.pem" "$VAULT_CERTS_DIR/ca.pem"
echo "  CA: $VAULT_CERTS_DIR/ca.pem"
echo "  Vault: $VAULT_PEM"

# ========== 生成服务端证书 ==========
echo "=== 生成服务端证书 ==="
for name in "${SERVER_NAMES[@]}"; do
    echo "  生成 $name 服务端证书..."
    openssl genrsa -out "$OUT_DIR/server/${name}.key" 2048 2>/dev/null
    openssl req -new -key "$OUT_DIR/server/${name}.key" \
        -subj "/CN=$name" \
        -out "$OUT_DIR/server/${name}.csr" 2>/dev/null
    # SAN extension: DNS name = CN, IP = 127.0.0.1
    cat > "$OUT_DIR/server/${name}.ext" <<EOF
subjectAltName = @alt_names
[alt_names]
DNS.1 = $name
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF
    openssl x509 -req -in "$OUT_DIR/server/${name}.csr" \
        -CA "$OUT_DIR/ca/ca.pem" -CAkey "$OUT_DIR/ca/ca.key" \
        -CAcreateserial \
        -out "$OUT_DIR/server/${name}.pem" \
        -days $DAYS -sha256 \
        -extfile "$OUT_DIR/server/${name}.ext" 2>/dev/null
    rm -f "$OUT_DIR/server/${name}.csr" "$OUT_DIR/server/${name}.ext"
    chmod 600 "$OUT_DIR/server/${name}.key"
    echo "  $OUT_DIR/server/${name}.pem/.key"
done

echo ""
echo "=== 证书生成完成 ==="
echo "CA 指纹:"
openssl x509 -in "$OUT_DIR/ca/ca.pem" -noout -fingerprint -sha256 | tr -d ':' | sed 's/.*=//'

echo ""
echo "生产部署时请将 certs/ 目录挂载到容器内 /etc/koku/certs/"
