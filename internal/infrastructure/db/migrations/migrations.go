package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"github.com/resoul/api/internal/domain"
	"gorm.io/gorm"
)

// All returns the ordered list of migrations.
// Rules:
//   - Never remove or reorder existing entries — only append.
//   - Never call AutoMigrate outside of migrations.
//   - Each ID is unique and time-prefixed: YYYYMMDDHHMI_<description>.
func All() []*gormigrate.Migration {
	return []*gormigrate.Migration{
		{
			// Placeholder kept for history continuity — no-op.
			ID: "202404041700_initial_schema",
			Migrate: func(tx *gorm.DB) error {
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				return nil
			},
		},
		{
			// Creates the profiles table.
			// We reference domain.Profile directly so the migration stays in sync
			// with the entity definition — no duplicated column lists.
			// Note: no FK to auth.users because that table lives in the Supabase-managed
			// auth schema and cross-schema FKs are fragile in hosted environments.
			ID: "202504240001_create_profiles",
			Migrate: func(tx *gorm.DB) error {
				return tx.AutoMigrate(&domain.Profile{})
			},
			Rollback: func(tx *gorm.DB) error {
				return tx.Migrator().DropTable(&domain.Profile{})
			},
		},
	}
}
