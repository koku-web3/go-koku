# syntax=docker/dockerfile:1

# 基础镜像：开源版 FROM hashicorp/vault:<version_tag>
FROM hashicorp/vault:2.1

# ---------- 显式切换为 root，获得文件操作权限 ----------
# 因为hashicorp/vault:2.0以 vault 用户运行
USER root

# ---------- 拷贝配置文件 ----------
# 把本地准备好的所有节点 hcl 配置文件一次性拷进镜像里（每个节点启动时按 NODE_IDX 选用自己的那份）
COPY local-config/hcl/vault-*.hcl /vault/config/hcl/

COPY local-config/policy/*.hcl /vault/config/policy/

# ---------- 创建 Vault 运行所需的数据/插件目录 ----------
# Raft 存储数据目录（每个节点独立保存自己的 raft 日志和数据）
# 注意: /vault/data 是 bind mount 点（见 vault.compose.yml 各节点 volumes 配置），
#       容器内的这个空目录会被宿主机 ../data/N 目录覆盖，仅作占位用途
RUN mkdir /vault/data/
# 自定义/企业插件目录
RUN mkdir /vault/plugins/
# 插件运行时临时目录
RUN mkdir /vault/plugins/tmp

# ---------- 切换回 root 以便修正目录权限 ----------
# hashicorp/vault 镜像默认以 UID=100 的 vault 用户运行。
# bind mount 进来的宿主机目录属主是宿主机用户（如 UID=501），
# 会导致容器内 vault 用户（UID=100）写不进去 /vault/data。
# 解决方案：要求宿主机在创建 data 目录时执行
#   sudo chown -R 100:100 ../data/1 ../data/2 ../data/3
# 或 sudo chmod -R 777 ../data/{1,2,3}
# 镜像内对未挂载的 plugins 目录修正属主，避免 vault 用户无法写入插件
USER root
RUN chown -R vault:vault /vault/plugins /vault/plugins/tmp
USER vault

# ---------- 启动命令 ----------
# 根据环境变量 NODE_IDX 动态选择加载哪个节点的配置文件
# 例如 NODE_IDX=1 时会加载 /vault/config/hcl/vault-1.hcl
CMD vault server -config=${VAULT_CONFIG}/hcl/vault-${NODE_IDX}.hcl