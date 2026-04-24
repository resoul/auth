package migrations

import (
	"github.com/go-gormigrate/gormigrate/v2"
	"gorm.io/gorm"
)

// All returns the ordered list of migrations.
// Never remove or reorder existing entries — only append new ones.
func All() []*gormigrate.Migration {
	return []*gormigrate.Migration{
		{
			// 202404041700 — initial placeholder kept for history continuity.
			ID: "202404041700_initial_schema",
			Migrate: func(tx *gorm.DB) error {
				return nil
			},
			Rollback: func(tx *gorm.DB) error {
				return nil
			},
		},
		{
			// 202504240001 — profiles table.
			// Stores application-level user data separate from auth.users.
			// References auth.users(id) via user_id; we do NOT use a FK constraint
			// because auth.users lives in the Supabase-managed auth schema.
			ID: "202504240001_create_profiles",
			Migrate: func(tx *gorm.DB) error {
				return tx.Exec(`
					CREATE TABLE IF NOT EXISTS profiles (
						id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
						user_id     UUID        NOT NULL UNIQUE,
						display_name TEXT,
						avatar_url  TEXT,
						bio         TEXT,
						created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
						updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
					);

					CREATE INDEX IF NOT EXISTS idx_profiles_user_id ON profiles (user_id);
				`).Error
			},
			Rollback: func(tx *gorm.DB) error {
				return tx.Exec(`
					DROP INDEX IF EXISTS idx_profiles_user_id;
					DROP TABLE  IF EXISTS profiles;
				`).Error
			},
		},
	}
}
