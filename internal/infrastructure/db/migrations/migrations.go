package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

func All() []*gormigrate.Migration {
	return []*gormigrate.Migration{
		{
			ID: "202404041700_initial_schema",
			Migrate: func(tx *gorm.DB) error {
				return tx.AutoMigrate()
			},
			Rollback: func(tx *gorm.DB) error {
				return tx.Migrator().DropTable()
			},
		},
	}
}
