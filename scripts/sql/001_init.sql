-- =====================================================
-- Go-Koku 数据库初始化脚本
-- 用途：创建数据库和初始化 chains 表数据
-- =====================================================

-- 1. 创建数据库
CREATE DATABASE IF NOT EXISTS kokudb DEFAULT CHARACTER SET utf8mb4 DEFAULT COLLATE utf8mb4_unicode_ci;

-- 授权给 compose 中的应用账号。
-- docker-compose 的 MYSQL_DATABASE 只会给 MYSQL_USER 授权到该库；若该值与
-- kokudb 不一致（或数据卷是在旧配置下初始化的），应用就会报
-- "Access denied for user 'koku'@'%' to database 'kokudb'"。
-- 这里显式补一次授权，保证与 [db] 配置一致。
GRANT ALL PRIVILEGES ON kokudb.* TO 'koku'@'%';
FLUSH PRIVILEGES;

-- 使用数据库
USE kokudb;

-- =====================================================
-- 2. 创建 chains 表（如果不存在）
-- =====================================================
CREATE TABLE IF NOT EXISTS `chains` (
    `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `chain_code` VARCHAR(36) NOT NULL COMMENT '区块链代码，如 bitcoin、ethereum',
    `base_coin` VARCHAR(10) NOT NULL COMMENT '主链币，如 btc、eth',
    `key_type` VARCHAR(36) NOT NULL COMMENT '密钥类型,如 ecdsa-secp256k1、ecdsa-secp256r1、eddsa-ed25519',
    `rpc_url` VARCHAR(256) NOT NULL COMMENT '区块链RPC地址',
    `explorer_url` VARCHAR(256) COMMENT '区块链浏览器地址',
    `website_url` VARCHAR(256) COMMENT '官方网站地址',
    `confirmation_count` INT UNSIGNED NOT NULL DEFAULT 6 COMMENT '入账最低确认数',
    `tx_builder_serv_grpc` VARCHAR(256) NOT NULL COMMENT '该链对应的交易构造gRPC地址',
    `tx_builder_serv_http` VARCHAR(256) NOT NULL COMMENT '该链对应的交易构造HTTP地址',
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `idx_chain_code` (`chain_code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='区块链网络表';

-- =====================================================
-- 3. 插入初始数据
-- =====================================================

-- Ethereum Sepolia 测试网配置
-- 注意：tx_builder_serv_grpc 必须是 txbuilder 容器在 compose 网络中的地址
INSERT INTO `chains` (
    `chain_code`,
    `base_coin`,
    `key_type`,
    `rpc_url`,
    `explorer_url`,
    `confirmation_count`,
    `tx_builder_serv_grpc`,
    `tx_builder_serv_http`
) VALUES (
    'ethereum',
    'eth',
    'ecdsa-secp256k1',
    'https://ethereum-sepolia-rpc.publicnode.com',
    'https://sepolia.etherscan.io/',
    12,
    'txbuilder-ethereum:51051',
    'http://127.0.0.1:81051'
) ON DUPLICATE KEY UPDATE
    `base_coin` = VALUES(`base_coin`),
    `rpc_url` = VALUES(`rpc_url`),
    `explorer_url` = VALUES(`explorer_url`),
    `confirmation_count` = VALUES(`confirmation_count`),
    `tx_builder_serv_grpc` = VALUES(`tx_builder_serv_grpc`),
    `tx_builder_serv_http` = VALUES(`tx_builder_serv_http`);
