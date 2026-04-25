package di

import (
	"context"
	"fmt"
	"time"

	"github.com/resoul/api/internal/config"
	"github.com/resoul/api/internal/domain"
	infradb "github.com/resoul/api/internal/infrastructure/db"
	"github.com/resoul/api/internal/service"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Container is the single composition root for the application.
// It is constructed once in cmd/serve.go and closed on shutdown.
// Handlers and services receive only the specific fields they need —
// never the full Container.
type Container struct {
	Config         *config.Config
	DB             *gorm.DB
	ProfileService domain.ProfileService
}

func NewContainer(ctx context.Context) (*Container, error) {
	cfg := config.Init(ctx)

	db, err := openDB(cfg.DB.DSN)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	profileRepo := infradb.NewProfileRepository(db)
	profileSvc := service.NewProfileService(profileRepo)

	return &Container{
		Config:         cfg,
		DB:             db,
		ProfileService: profileSvc,
	}, nil
}

func (c *Container) Close() error {
	if c == nil || c.DB == nil {
		return nil
	}

	sqlDB, err := c.DB.DB()
	if err != nil {
		return fmt.Errorf("get underlying sql.DB: %w", err)
	}

	return sqlDB.Close()
}

// openDB opens a PostgreSQL connection with sane pool defaults.
func openDB(dsn string) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
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

	return db, nil
}
