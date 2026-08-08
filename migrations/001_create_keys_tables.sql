-- Keys Management Schema for FINANCE Compliance
-- 密钥生命周期管理数据库表

-- 创建 master_keys 表
-- 存储 HD 主密钥的元数据和加密的种子
CREATE TABLE IF NOT EXISTS master_keys (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    chain_code      VARCHAR(36) NOT NULL,
    key_name        VARCHAR(64) NOT NULL,
    seed_ciphertext TEXT NOT NULL COMMENT 'Vault Transit Engine 加密的 HD 种子',
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    status          TINYINT NOT NULL DEFAULT 0 COMMENT '0=ACTIVE, 1=REVOKED, 2=DELETED',
    
    UNIQUE INDEX idx_chain_code (chain_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 创建 keys 表
-- 存储从主密钥派生的子密钥
CREATE TABLE IF NOT EXISTS keys (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    master_key_id   BIGINT UNSIGNED NOT NULL,
    chain_code      VARCHAR(36) NOT NULL COMMENT '链代码: ethereum, bitcoin 等',
    key_name        VARCHAR(64) NOT NULL COMMENT '密钥名称: eth-operational-0',
    key_usage       TINYINT NOT NULL COMMENT '0=OPERATIONAL, 1=USER, 2=BACKUP',
    address_index   INT UNSIGNED NOT NULL DEFAULT 0,
    bip44_path      VARCHAR(64) NOT NULL COMMENT 'BIP-44 路径: m/44''/60''/0''/1/0',
    key_context     VARCHAR(128) NOT NULL COMMENT 'Base64(SHA256(bip44_path)) 用于 Vault context',
    ciphertext      TEXT NOT NULL COMMENT 'Vault Transit Engine 加密的私钥',
    public_key      VARCHAR(256) NOT NULL COMMENT '公钥 (Hex)',
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    status          TINYINT NOT NULL DEFAULT 0 COMMENT '0=ACTIVE, 1=REVOKED, 2=DELETED',
    
    INDEX idx_chain_usage (chain_code, key_usage),
    INDEX idx_key_context (key_context),
    INDEX idx_master_key (master_key_id),
    INDEX idx_status (status),
    
    FOREIGN KEY (master_key_id) REFERENCES master_keys(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 创建 audit_logs 表
-- 记录所有密钥操作，用于合规审计
CREATE TABLE IF NOT EXISTS audit_logs (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    trace_id        VARCHAR(64) NOT NULL COMMENT '链路跟踪 ID',
    key_id          BIGINT UNSIGNED NOT NULL COMMENT '关联的密钥 ID',
    operation       VARCHAR(32) NOT NULL COMMENT '操作类型: CREATE_KEY, SIGN, VERIFY, REVOKE',
    request_hash    VARCHAR(128) COMMENT '请求消息的 SHA256 哈希',
    signature       VARCHAR(512) COMMENT '签名结果 (如果适用)',
    client_ip       VARCHAR(45) COMMENT '客户端 IP 地址',
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_trace (trace_id),
    INDEX idx_key_time (key_id, created_at),
    INDEX idx_operation (operation),
    
    FOREIGN KEY (key_id) REFERENCES keys(id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
