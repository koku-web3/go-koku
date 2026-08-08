// Package repository 提供数据库操作接口
package repository

import (
	"context"
	"fmt"

	"gorm.io/gorm"

	"github.com/koku-web3/go-koku/internal/coordinator/model"
)

// KeyRepository 密钥仓储接口
type KeyRepository interface {
	// MasterKey 操作
	CreateMasterKey(ctx context.Context, key *model.MasterKey) error
	GetMasterKeyByChainCode(ctx context.Context, chainCode string) (*model.MasterKey, error)

	// Key 操作
	CreateKey(ctx context.Context, key *model.Key) error
	GetKeyByID(ctx context.Context, id uint64) (*model.Key, error)
	GetKeyByName(ctx context.Context, keyName string) (*model.Key, error)
	GetKeysByChainCode(ctx context.Context, chainCode string) ([]*model.Key, error)
	GetKeysByUsage(ctx context.Context, chainCode string, usage model.KeyUsage) ([]*model.Key, error)
	UpdateKeyStatus(ctx context.Context, id uint64, status model.KeyStatus) error

	// AuditLog 操作
	CreateAuditLog(ctx context.Context, log *model.AuditLog) error
}

// GORMKeyRepository GORM 实现的密钥仓储
type GORMKeyRepository struct {
	db *gorm.DB
}

// NewGORMKeyRepository 创建 GORM 密钥仓储
func NewGORMKeyRepository(db *gorm.DB) *GORMKeyRepository {
	return &GORMKeyRepository{db: db}
}

// CreateMasterKey 创建主密钥
func (r *GORMKeyRepository) CreateMasterKey(ctx context.Context, key *model.MasterKey) error {
	result := r.db.WithContext(ctx).Create(key)
	if result.Error != nil {
		return fmt.Errorf("failed to create master key: %w", result.Error)
	}
	return nil
}

// GetMasterKeyByChainCode 根据链代码获取主密钥
func (r *GORMKeyRepository) GetMasterKeyByChainCode(ctx context.Context, chainCode string) (*model.MasterKey, error) {
	var key model.MasterKey
	result := r.db.WithContext(ctx).Where("chain_code = ? AND status = ?", chainCode, model.KeyStatusActive).First(&key)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get master key: %w", result.Error)
	}
	return &key, nil
}

// CreateKey 创建子密钥
func (r *GORMKeyRepository) CreateKey(ctx context.Context, key *model.Key) error {
	result := r.db.WithContext(ctx).Create(key)
	if result.Error != nil {
		return fmt.Errorf("failed to create key: %w", result.Error)
	}
	return nil
}

// GetKeyByID 根据 ID 获取密钥
func (r *GORMKeyRepository) GetKeyByID(ctx context.Context, id uint64) (*model.Key, error) {
	var key model.Key
	result := r.db.WithContext(ctx).Where("id = ? AND status = ?", id, model.KeyStatusActive).First(&key)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get key: %w", result.Error)
	}
	return &key, nil
}

// GetKeyByName 根据名称获取密钥
func (r *GORMKeyRepository) GetKeyByName(ctx context.Context, keyName string) (*model.Key, error) {
	var key model.Key
	result := r.db.WithContext(ctx).Where("key_name = ? AND status = ?", keyName, model.KeyStatusActive).First(&key)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get key: %w", result.Error)
	}
	return &key, nil
}

// GetKeysByChainCode 根据链代码获取所有密钥
func (r *GORMKeyRepository) GetKeysByChainCode(ctx context.Context, chainCode string) ([]*model.Key, error) {
	var keys []*model.Key
	result := r.db.WithContext(ctx).Where("chain_code = ? AND status = ?", chainCode, model.KeyStatusActive).Find(&keys)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to get keys: %w", result.Error)
	}
	return keys, nil
}

// GetKeysByUsage 根据链代码和用途获取密钥
func (r *GORMKeyRepository) GetKeysByUsage(ctx context.Context, chainCode string, usage model.KeyUsage) ([]*model.Key, error) {
	var keys []*model.Key
	result := r.db.WithContext(ctx).Where("chain_code = ? AND key_usage = ? AND status = ?", chainCode, usage, model.KeyStatusActive).Find(&keys)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to get keys: %w", result.Error)
	}
	return keys, nil
}

// UpdateKeyStatus 更新密钥状态
func (r *GORMKeyRepository) UpdateKeyStatus(ctx context.Context, id uint64, status model.KeyStatus) error {
	result := r.db.WithContext(ctx).Model(&model.Key{}).Where("id = ?", id).Update("status", status)
	if result.Error != nil {
		return fmt.Errorf("failed to update key status: %w", result.Error)
	}
	return nil
}

// CreateAuditLog 创建审计日志
func (r *GORMKeyRepository) CreateAuditLog(ctx context.Context, log *model.AuditLog) error {
	result := r.db.WithContext(ctx).Create(log)
	if result.Error != nil {
		return fmt.Errorf("failed to create audit log: %w", result.Error)
	}
	return nil
}
