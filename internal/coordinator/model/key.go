// Package model 定义了数据库模型
package model

import (
	"time"
)

// KeyStatus 密钥状态
type KeyStatus int

const (
	KeyStatusActive KeyStatus = iota
	KeyStatusRevoked
	KeyStatusDeleted
)

func (s KeyStatus) String() string {
	switch s {
	case KeyStatusActive:
		return "active"
	case KeyStatusRevoked:
		return "revoked"
	case KeyStatusDeleted:
		return "deleted"
	default:
		return "unknown"
	}
}

// KeyUsage 密钥用途
type KeyUsage int

const (
	KeyUsageOperational KeyUsage = iota
	KeyUsageUser
	KeyUsageBackup
)

func (u KeyUsage) String() string {
	switch u {
	case KeyUsageOperational:
		return "operational"
	case KeyUsageUser:
		return "user"
	case KeyUsageBackup:
		return "backup"
	default:
		return "unknown"
	}
}

// MasterKey 主密钥表
// 存储 HD 主密钥的元数据和加密的种子
type MasterKey struct {
	ID             uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	ChainCode      string    `gorm:"type:varchar(36);uniqueIndex;not null" json:"chain_code"`
	KeyName        string    `gorm:"type:varchar(64);not null" json:"key_name"`
	SeedCiphertext string    `gorm:"type:text;not null" json:"seed_ciphertext"` // Vault 加密的 HD 种子
	CreatedAt      time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt      time.Time `gorm:"autoUpdateTime" json:"updated_at"`
	Status         KeyStatus `gorm:"type:tinyint;default:0" json:"status"`
}

func (MasterKey) TableName() string {
	return "master_keys"
}

// Key 子密钥表
// 存储从主密钥派生的子密钥的加密私钥和公钥
type Key struct {
	ID           uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	MasterKeyID  uint64    `gorm:"index;not null" json:"master_key_id"`
	ChainCode    string    `gorm:"type:varchar(36);not null" json:"chain_code"`
	KeyName      string    `gorm:"type:varchar(64);not null" json:"key_name"`
	KeyUsage     KeyUsage  `gorm:"type:tinyint;not null" json:"key_usage"`
	AddressIndex uint32    `gorm:"not null;default:0" json:"address_index"`
	BIP44Path    string    `gorm:"type:varchar(64);not null" json:"bip44_path"`
	KeyContext   string    `gorm:"type:varchar(128);not null" json:"key_context"` // SHA256(path) 作为 Vault context
	Ciphertext   string    `gorm:"type:text;not null" json:"ciphertext"`          // Vault 加密的私钥
	PublicKey    string    `gorm:"type:varchar(256);not null" json:"public_key"`  // 公钥 (Hex)
	CreatedAt    time.Time `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt    time.Time `gorm:"autoUpdateTime" json:"updated_at"`
	Status       KeyStatus `gorm:"type:tinyint;default:0" json:"status"`
}

func (Key) TableName() string {
	return "keys"
}

// AuditLog 审计日志表
// 记录所有密钥操作，用于合规审计
type AuditLog struct {
	ID          uint64    `gorm:"primaryKey;autoIncrement" json:"id"`
	TraceID     string    `gorm:"type:varchar(64);index;not null" json:"trace_id"`
	KeyID       uint64    `gorm:"index;not null" json:"key_id"`
	Operation   string    `gorm:"type:varchar(32);not null" json:"operation"` // CREATE_KEY, SIGN, etc.
	RequestHash string    `gorm:"type:varchar(128)" json:"request_hash"`      // 请求消息的 SHA256
	Signature   string    `gorm:"type:varchar(512)" json:"signature"`         // 签名结果
	ClientIP    string    `gorm:"type:varchar(45)" json:"client_ip"`
	CreatedAt   time.Time `gorm:"autoCreateTime;index" json:"created_at"`
}

func (AuditLog) TableName() string {
	return "audit_logs"
}
