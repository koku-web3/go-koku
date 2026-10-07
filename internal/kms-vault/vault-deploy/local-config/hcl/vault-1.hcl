# ================== 基础设置 ==================
ui              = true      # 启用 Web UI（可通过浏览器访问 :8200）
disable_mlock   = true      # 关闭内存锁定（容器环境常见做法，因为容器一般没有 mlock 权限）

# ================== 非回环网络接口配置 ==================
# api_addr：本节点对外提供 API 服务的地址，其他节点/客户端通过这个地址访问它
api_addr     = "https://kms-vault-1:8200"
# cluster_addr：节点间内部通信（Raft 复制、leader 转发等）使用的地址，端口固定为 8201
cluster_addr = "https://kms-vault-1:8201"
# cluster_name：集群名称，同一集群内所有节点必须保持一致
cluster_name = "kms-vault"

# ================== 插件配置 ==================
plugin_directory = "/vault/plugins/"      # 自定义/企业插件存放目录
plugin_tmpdir    = "/vault/plugins/tmp"   # 插件运行时临时文件目录（即使暂不使用插件也建议先配置好，
                                           # 因为后续修改插件目录需要重启整个集群）

# ================== 监听器（Listener）配置 ==================
listener "tcp" {
  address            = "[::]:8200"                       # 监听所有 IPv6/IPv4 地址的 8200 端口
  tls_disable        = "false"                           # 必须启用 TLS（HA 集群强制要求，不能关闭）
  tls_cert_file      = "/vault/certs/vault.pem"   # TLS 证书
  tls_key_file       = "/vault/certs/vault.key"   # TLS 私钥
  tls_client_ca_file = "/vault/certs/ca.pem"      # 用于验证客户端/其他节点身份的 CA 证书
}

# ================== 集成存储（Integrated Storage / Raft）—— 高可用的核心 ==================
storage "raft" {

  path    = "/vault/data"        # Raft 数据（日志、快照等）在容器内的存储路径，对应 Dockerfile 里创建的目录
  node_id = "kms-vault-1"       # 本节点在 Raft 集群中的唯一标识，通常直接用容器名，确保集群内唯一

  # --- 声明如何找到并加入集群中的"其他节点" ---
  # 每个 retry_join 块对应集群里的一个"对端节点"
  # 节点启动时会依次尝试连接这些地址，只要能连上任意一个已经在集群里的节点即可完成加入

  # 加入节点 2
  retry_join {
    leader_api_addr         = "https://kms-vault-2:8200"   # 对端节点的 API 地址
    leader_client_cert_file = "/vault/certs/vault.pem"  # 用于向对端证明自己身份的证书
    leader_client_key_file  = "/vault/certs/vault.key"  # 对应私钥
    leader_ca_cert_file     = "/vault/certs/ca.pem"     # 用于验证对端证书的 CA
  }

  # 加入节点 3
  retry_join {
    leader_api_addr         = "https://kms-vault-3:8200"
    leader_client_cert_file = "/vault/certs/vault.pem"
    leader_client_key_file  = "/vault/certs/vault.key"
    leader_ca_cert_file     = "/vault/certs/ca.pem"
  }
}