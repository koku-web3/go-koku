// Package model 定义了数据库模型
package model

import (
	"time"
)

// AllModels 所有需要迁移的模型,用于启动时自动建表
var AllModels = []interface{}{
	&Chain{},
	&CoreKey{},
	&MasterKey{},
	&ChindKey{},
	&AuditLog{},
}

// Chain 区块链网络表
// 存储区块链网络配置信息
type Chain struct {
	ID                uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	ChainCode         string    `gorm:"type:varchar(36);uniqueIndex;not null;comment:区块链代码,如 bitcoin、ethereum" json:"chain_code"`
	BaseCoin          string    `gorm:"type:varchar(10);not null;comment:主链币,如 btc、eth" json:"base_coin"`
	RPCURL            string    `gorm:"type:varchar(256);not null;comment:区块链RPC地址" json:"rpc_url"`
	ExplorerURL       string    `gorm:"type:varchar(256);comment:区块链浏览器地址" json:"explorer_url"`
	WebsiteURL        string    `gorm:"type:varchar(256);comment:官方网站地址" json:"website_url"`
	ConfirmationCount uint      `gorm:"not null;default:6;comment:入账最低确认数" json:"confirmation_count"`
	TxBuilderServGRPC string    `gorm:"type:varchar(256);not null;comment:该链对应的交易构造gRPC地址" json:"tx_builder_serv_grpc"`
	TxBuilderServHTTP string    `gorm:"type:varchar(256);not null;comment:该链对应的交易构造HTTP地址" json:"tx_builder_serv_http"`
	CreatedAt         time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt         time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

func (Chain) TableName() string {
	return "chains"
}

// CoreKey 核心密钥表
// 存储 BIP-44 中第三层级 Account （m/44'/coinType'/account'）密钥
// 每个链存储两条数据（运营密钥和用户密钥的）
type CoreKey struct {
	ID                 uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	ChainCode          string    `gorm:"type:varchar(36);uniqueIndex:idx_chain_usage;not null;comment:区块链代码" json:"chain_code"`
	KeyUsage           uint8     `gorm:"type:tinyint;uniqueIndex:idx_chain_usage;not null;comment:0=OPERATIONAL, 1=USER" json:"key_usage"`
	Bip32KeyCiphertext string    `gorm:"type:text;not null;comment:加密后的bip32主密钥 hex 格式" json:"bip32key_ciphertext"`
	DEK_Ciphertext     string    `gorm:"type:text;comment:DEK 密文,用于信封加密" json:"dek_ciphertext"`
	Context            string    `gorm:"type:varchar(128);not null;comment:密钥派生上下文标识符, 1-36必填, 唯一" json:"context"`
	Bip44Path          string    `gorm:"type:varchar(64);not null;comment:BIP-44 路径字符串" json:"bip44_path"`
	CreatedAt          time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt          time.Time `gorm:"autoUpdateTime" json:"updated_at"`
	IsDeleted          bool      `gorm:"default:false;comment:软删除标记" json:"is_deleted"`
}

func (CoreKey) TableName() string {
	return "core_keys"
}

// MasterKey 主密钥表
// 存储 HD 主密钥的元数据和加密的种子 seed
type MasterKey struct {
	ID             uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	ChainCode      string    `gorm:"type:varchar(36);uniqueIndex;not null" json:"chain_code"`
	KeyType        string    `gorm:"type:varchar(36);not null;comment:密钥类型,如 ecdsa-secp256k1、ecdsa-secp256r1、eddsa-ed25519" json:"key_type"`
	SeedCiphertext string    `gorm:"type:text;not null;comment:HD seed 经 Vault 信封加密后的密文" json:"seed_ciphertext"`
	DEK_Ciphertext string    `gorm:"type:text;comment:DEK 密文,用于信封加密" json:"dek_ciphertext"`
	Context        string    `gorm:"type:varchar(128);not null;comment:密钥派生上下文标识符, 1-36必填, 唯一" json:"context"`
	Bip44Path      string    `gorm:"type:varchar(64);not null;comment:BIP-44路径,格式m/44'/coinType" json:"bip44_path"`
	CreatedAt      time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt      time.Time `gorm:"autoUpdateTime" json:"updated_at"`
	IsDeleted      bool      `gorm:"default:false;comment:软删除标记" json:"is_deleted"`
}

func (MasterKey) TableName() string {
	return "master_keys"
}

// ChindKey 子密钥表
// 存储从主密钥派生的子密钥的加密私钥和公钥
type ChindKey struct {
	ID             uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	ChainCode      string    `gorm:"type:varchar(36);index:idx_chain_usage;not null;comment:链代码: ethereum, bitcoin 等" json:"chain_code"`
	KeyUsage       uint8     `gorm:"type:tinyint;index:idx_chain_usage;not null;comment:0=OPERATIONAL, 1=USER, 2=BACKUP" json:"key_usage"`
	AccountIndex   uint32    `gorm:"not null;default:0;comment:账户索引, 对应Bip44的account_index层级" json:"account_index"`
	BIP44Path      string    `gorm:"type:varchar(64);not null;comment:BIP-44 路径: m/44'/60'/0'/1/0" json:"bip44_path"`
	KeyContext     string    `gorm:"type:varchar(128);not null;comment:Base64(SHA256(bip44_path)) 用于 Vault context" json:"key_context"`
	Ciphertext     string    `gorm:"type:text;not null;comment:加密后的 DER 格式密钥, 返回base64编码格式" json:"ciphertext"`
	DEK_Ciphertext string    `gorm:"type:text;comment:DEK 密文,用于信封加密" json:"dek_ciphertext"`
	PublicKey      string    `gorm:"type:varchar(256);not null;comment:公钥 (Hex)" json:"public_key"`
	KeyAddress     string    `gorm:"type:varchar(128);not null;comment:地址" json:"key_address"`
	CreatedAt      time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt      time.Time `gorm:"autoUpdateTime" json:"updated_at"`
	IsDeleted      bool      `gorm:"default:false;comment:软删除标记" json:"is_deleted"`
}

func (ChindKey) TableName() string {
	return "child_keys"
}

// AuditLog 审计日志表
// 记录所有密钥操作,用于合规审计
type AuditLog struct {
	ID          uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	TraceID     string    `gorm:"type:varchar(64);index;not null;comment:链路跟踪 ID" json:"trace_id"`
	KeyID       uint64    `gorm:"index;not null;comment:关联的密钥 ID" json:"key_id"`
	Operation   string    `gorm:"type:varchar(32);not null;comment:操作类型: CREATE_KEY, SIGN, VERIFY, REVOKE" json:"operation"`
	RequestHash string    `gorm:"type:varchar(128);comment:请求消息的 SHA256 哈希" json:"request_hash"`
	Signature   string    `gorm:"type:varchar(512);comment:签名结果 (如果适用)" json:"signature"`
	ClientIP    string    `gorm:"type:varchar(45);comment:客户端 IP 地址" json:"client_ip"`
	CreatedAt   time.Time `gorm:"autoCreateTime;index" json:"created_at"`
}

func (AuditLog) TableName() string {
	return "audit_logs"
}
