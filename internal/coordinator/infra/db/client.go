// Package db 提供数据库连接管理
package db

import (
	"fmt"
	"time"

	log "github.com/koku-web3/go-koku/pkg/logko"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Config 数据库连接配置
type Config struct {
	Host         string
	Port         int
	User         string
	Password     string
	Database     string
	MaxOpenConns int
	MaxIdleConns int
}

// NewConfig 从 config.Config 转换
func NewConfig(cfg Config) Config {
	return Config{
		Host:         cfg.Host,
		Port:         cfg.Port,
		User:         cfg.User,
		Password:     cfg.Password,
		Database:     cfg.Database,
		MaxOpenConns: cfg.MaxOpenConns,
		MaxIdleConns: cfg.MaxIdleConns,
	}
}

// NewClient 创建数据库连接
func NewClient(cfg Config) (*gorm.DB, error) {
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.User,
		cfg.Password,
		cfg.Host,
		cfg.Port,
		cfg.Database,
	)

	gormConfig := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	}

	db, err := gorm.Open(mysql.Open(dsn), gormConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database instance: %w", err)
	}

	if cfg.MaxOpenConns > 0 {
		sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	}
	if cfg.MaxIdleConns > 0 {
		sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	}
	sqlDB.SetConnMaxLifetime(time.Hour)

	log.Info("Database connection established", "host", cfg.Host, "database", cfg.Database)

	return db, nil
}

// Migrate 执行数据库迁移，如果表不存在则创建
func Migrate(db *gorm.DB, models ...interface{}) error {
	for _, model := range models {
		if !db.Migrator().HasTable(model) {
			if err := db.Migrator().CreateTable(model); err != nil {
				return fmt.Errorf("failed to create table for %T: %w", model, err)
			}
			log.Info("Table created", "table", getTableName(db, model))
		}
	}
	return nil
}

// getTableName 获取模型对应的表名
func getTableName(db *gorm.DB, model interface{}) string {
	if tn, ok := model.(interface{ TableName() string }); ok {
		return tn.TableName()
	}
	stmt := &gorm.Statement{DB: db}
	if err := stmt.Parse(model); err == nil {
		return stmt.Schema.Table
	}
	return ""
}
