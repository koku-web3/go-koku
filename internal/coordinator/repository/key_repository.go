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
	// DB 返回底层 gorm.DB，用于事务管理
	DB() *gorm.DB

	// MasterKey 操作
	CreateMasterKey(ctx context.Context, key *model.MasterKey) error
	GetMasterKeyByChainCode(ctx context.Context, chainCode string) (*model.MasterKey, error)

	// CoreKey 操作
	CreateCoreKey(ctx context.Context, key *model.CoreKey) error
	GetCoreKeyByChainCodeAndUsage(ctx context.Context, chainCode string, usage uint32) (*model.CoreKey, error)
	GetCoreKeyByChainCodeAllStatus(ctx context.Context, chainCode string, usage uint32) (*model.CoreKey, error)
	GetCoreKeyCountByChainCode(ctx context.Context, chainCode string) (uint32, error)

	// Key 操作
	CreateKey(ctx context.Context, key *model.ChindKey) error
	CreateKeys(ctx context.Context, keys []*model.ChindKey) error
	GetKeyByID(ctx context.Context, id uint64) (*model.ChindKey, error)
	GetKeyByName(ctx context.Context, keyName string) (*model.ChindKey, error)
	GetKeysByChainCode(ctx context.Context, chainCode string) ([]*model.ChindKey, error)
	GetKeysByUsage(ctx context.Context, chainCode string, usage uint32) ([]*model.ChindKey, error)
	GetMaxAccountIndex(ctx context.Context, chainCode string, usage uint32) (uint32, error)
	GetKeyByAddress(ctx context.Context, chainCode, address string) (*model.ChindKey, error)

	// Chain 操作
	CreateChain(ctx context.Context, chain *model.Chain) error
	GetChainByCode(ctx context.Context, chainCode string) (*model.Chain, error)
	GetAllChains(ctx context.Context) ([]*model.Chain, error)

	// AuditLog 操作
	CreateAuditLog(ctx context.Context, log *model.AuditLog) error

	// InsertGenesisRecordsAtomic 操作（事务保证原子性）
	InsertGenesisRecordsAtomic(ctx context.Context, masterKey *model.MasterKey, coreKeys []*model.CoreKey) error
}

// GORMKeyRepository GORM 实现的密钥仓储
type GORMKeyRepository struct {
	db *gorm.DB
}

// NewGORMKeyRepository 创建 GORM 密钥仓储
func NewGORMKeyRepository(db *gorm.DB) *GORMKeyRepository {
	return &GORMKeyRepository{db: db}
}

// DB 返回底层 gorm.DB，用于事务管理
func (r *GORMKeyRepository) DB() *gorm.DB {
	return r.db
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
	result := r.db.WithContext(ctx).Where("chain_code = ? AND is_deleted = ?", chainCode, false).First(&key)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get master key: %w", result.Error)
	}
	return &key, nil
}

// CreateCoreKey 创建核心密钥
func (r *GORMKeyRepository) CreateCoreKey(ctx context.Context, key *model.CoreKey) error {
	result := r.db.WithContext(ctx).Create(key)
	if result.Error != nil {
		return fmt.Errorf("failed to create core key: %w", result.Error)
	}
	return nil
}

// GetCoreKeyByChainCodeAndUsage 根据链代码和密钥用途获取核心密钥
func (r *GORMKeyRepository) GetCoreKeyByChainCodeAndUsage(ctx context.Context, chainCode string, usage uint32) (*model.CoreKey, error) {
	var key model.CoreKey
	result := r.db.WithContext(ctx).Where("chain_code = ? AND key_usage = ? AND is_deleted = ?", chainCode, usage, false).First(&key)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get core key: %w", result.Error)
	}
	return &key, nil
}

// GetCoreKeyByChainCodeAllStatus 根据链代码和密钥用途获取核心密钥
func (r *GORMKeyRepository) GetCoreKeyByChainCodeAllStatus(ctx context.Context, chainCode string, usage uint32) (*model.CoreKey, error) {
	var key model.CoreKey
	result := r.db.WithContext(ctx).Where("chain_code = ? AND key_usage = ? AND is_deleted = ?", chainCode, usage, false).First(&key)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get core key: %w", result.Error)
	}
	return &key, nil
}

// GetCoreKeyCountByChainCode 统计指定链代码下的核心密钥数量
func (r *GORMKeyRepository) GetCoreKeyCountByChainCode(ctx context.Context, chainCode string) (uint32, error) {
	var count int64
	result := r.db.WithContext(ctx).
		Model(&model.CoreKey{}).
		Where("chain_code = ? AND is_deleted = ?", chainCode, false).
		Count(&count)
	if result.Error != nil {
		return 0, fmt.Errorf("failed to count core keys: %w", result.Error)
	}
	return uint32(count), nil
}

// CreateKey 创建子密钥
func (r *GORMKeyRepository) CreateKey(ctx context.Context, key *model.ChindKey) error {
	result := r.db.WithContext(ctx).Create(key)
	if result.Error != nil {
		return fmt.Errorf("failed to create key: %w", result.Error)
	}
	return nil
}

// CreateKeys 批量创建子密钥
func (r *GORMKeyRepository) CreateKeys(ctx context.Context, keys []*model.ChindKey) error {
	result := r.db.WithContext(ctx).Create(&keys)
	if result.Error != nil {
		return fmt.Errorf("failed to create keys: %w", result.Error)
	}
	return nil
}

// GetKeyByID 根据 ID 获取密钥
func (r *GORMKeyRepository) GetKeyByID(ctx context.Context, id uint64) (*model.ChindKey, error) {
	var key model.ChindKey
	result := r.db.WithContext(ctx).Where("id = ? AND is_deleted = ?", id, false).First(&key)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get key: %w", result.Error)
	}
	return &key, nil
}

// GetKeyByName 根据名称获取密钥
func (r *GORMKeyRepository) GetKeyByName(ctx context.Context, keyName string) (*model.ChindKey, error) {
	var key model.ChindKey
	result := r.db.WithContext(ctx).Where("key_name = ? AND is_deleted = ?", keyName, false).First(&key)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get key: %w", result.Error)
	}
	return &key, nil
}

// GetKeysByChainCode 根据链代码获取所有密钥
func (r *GORMKeyRepository) GetKeysByChainCode(ctx context.Context, chainCode string) ([]*model.ChindKey, error) {
	var keys []*model.ChindKey
	result := r.db.WithContext(ctx).Where("chain_code = ? AND is_deleted = ?", chainCode, false).Find(&keys)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to get keys: %w", result.Error)
	}
	return keys, nil
}

// GetKeysByUsage 根据链代码和用途获取密钥
func (r *GORMKeyRepository) GetKeysByUsage(ctx context.Context, chainCode string, usage uint32) ([]*model.ChindKey, error) {
	var keys []*model.ChindKey
	result := r.db.WithContext(ctx).Where("chain_code = ? AND key_usage = ? AND is_deleted = ?", chainCode, usage, false).Find(&keys)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to get keys: %w", result.Error)
	}
	return keys, nil
}

// GetMaxAccountIndex 获取指定链的最大账户索引
func (r *GORMKeyRepository) GetMaxAccountIndex(ctx context.Context, chainCode string, usage uint32) (uint32, error) {
	var maxIndex uint32
	// 这里的查询语句会生成如下 SQL:
	// SELECT COALESCE(MAX(account_index), 0) FROM `keys` WHERE chain_code = ? AND is_deleted = false;
	//
	// 是否使用索引取决于数据库中 `keys` 表的索引设计。
	// 如果 (chain_code, is_deleted, account_index) 或至少 (chain_code, is_deleted) 上有联合索引，则本查询会走索引，非常高效。
	//
	// 常见设计下 chain_code 通常会建索引，因此整个条件过滤会使用索引，MAX(account_index) 会在过滤后对较小子集聚合。
	// 时间复杂度通常为 O(logN)~O(M)，N为总记录数，M为满足 where 条件的记录数，且有索引时表现良好。
	result := r.db.WithContext(ctx).
		Model(&model.ChindKey{}).
		Where("chain_code = ? AND key_usage = ? AND is_deleted = ?", chainCode, usage, false).
		// 这里 Select("COALESCE(MAX(account_index), 0)") 的意思是：
		// 从 key 表中找到最大 account_index，如果没有记录（即 MAX(account_index) 结果为 NULL），就返回 0。
		// COALESCE 是 SQL 标准函数，用来返回第一个非 NULL 的值，这样即使表里没有数据也能安全返回 0。
		Select("COALESCE(MAX(account_index), 0)").
		Scan(&maxIndex)
	if result.Error != nil {
		return 0, fmt.Errorf("failed to get max account index: %w", result.Error)
	}
	return maxIndex, nil
}

// CreateChain 创建区块链配置
func (r *GORMKeyRepository) CreateChain(ctx context.Context, chain *model.Chain) error {
	result := r.db.WithContext(ctx).Create(chain)
	if result.Error != nil {
		return fmt.Errorf("failed to create chain: %w", result.Error)
	}
	return nil
}

// GetChainByCode 根据链代码获取区块链配置
func (r *GORMKeyRepository) GetChainByCode(ctx context.Context, chainCode string) (*model.Chain, error) {
	var chain model.Chain
	result := r.db.WithContext(ctx).Where("chain_code = ?", chainCode).First(&chain)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get chain: %w", result.Error)
	}
	return &chain, nil
}

// GetAllChains 获取所有区块链配置
func (r *GORMKeyRepository) GetAllChains(ctx context.Context) ([]*model.Chain, error) {
	var chains []*model.Chain
	result := r.db.WithContext(ctx).Find(&chains)
	if result.Error != nil {
		return nil, fmt.Errorf("failed to get all chains: %w", result.Error)
	}
	return chains, nil
}

// CreateAuditLog 创建审计日志
func (r *GORMKeyRepository) CreateAuditLog(ctx context.Context, log *model.AuditLog) error {
	result := r.db.WithContext(ctx).Create(log)
	if result.Error != nil {
		return fmt.Errorf("failed to create audit log: %w", result.Error)
	}
	return nil
}

// InsertGenesisRecordsAtomic 创建 Genesis 主密钥和核心密钥（事务保证原子性）
func (r *GORMKeyRepository) InsertGenesisRecordsAtomic(ctx context.Context, masterKey *model.MasterKey, coreKeys []*model.CoreKey) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(masterKey).Error; err != nil {
			return fmt.Errorf("failed to create master key: %w", err)
		}
		if err := tx.Create(coreKeys).Error; err != nil {
			return fmt.Errorf("failed to create core keys: %w", err)
		}
		return nil
	})
}

// GetKeyByAddress 根据链代码和地址获取密钥
func (r *GORMKeyRepository) GetKeyByAddress(ctx context.Context, chainCode, address string) (*model.ChindKey, error) {
	var key model.ChindKey
	result := r.db.WithContext(ctx).Where("chain_code = ? AND key_address = ? AND is_deleted = ?", chainCode, address, false).First(&key)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get key by address: %w", result.Error)
	}
	return &key, nil
}
