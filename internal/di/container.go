package di

import (
	"context"
	"time"

	"github.com/resoul/api/internal/config"
	"github.com/supabase-community/auth-go"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type Container struct {
	Config *config.Config
	DB     *gorm.DB
	Auth   auth.Client
}

func NewContainer(ctx context.Context) (*Container, error) {
	cfg := config.Init(ctx)

	db, err := gorm.Open(postgres.Open(cfg.DB.DSN), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	sqlDB.SetMaxOpenConns(25)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(time.Hour)

	authClient := auth.New(cfg.Auth.URL, cfg.Auth.APIKey)

	return &Container{
		Config: cfg,
		DB:     db,
		Auth:   authClient,
	}, nil
}

func (c *Container) Close() error {
	if c == nil {
		return nil
	}

	if c.DB != nil {
		sqlDB, err := c.DB.DB()
		if err == nil {
			return sqlDB.Close()
		}
	}

	return nil
}
