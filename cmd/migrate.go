package cmd

import (
	"fmt"

	"github.com/go-gormigrate/gormigrate/v2"
	"github.com/resoul/api/internal/config"
	"github.com/resoul/api/internal/infrastructure/db/migrations"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Run database migrations",
}

var migrateUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Apply all pending migrations",
	Run: func(cmd *cobra.Command, args []string) {
		cfg := config.Init(cmd.Context())
		db, err := gorm.Open(postgres.Open(cfg.DB.DSN), &gorm.Config{})
		if err != nil {
			logrus.Fatal(err)
		}

		m := gormigrate.New(db, gormigrate.DefaultOptions, migrations.All())

		if err = m.Migrate(); err != nil {
			logrus.Fatalf("Could not migrate: %v", err)
		}
		fmt.Println("Migration run successfully")
	},
}

var migrateDownCmd = &cobra.Command{
	Use:   "down",
	Short: "Rollback the last migration",
	Run: func(cmd *cobra.Command, args []string) {
		cfg := config.Init(cmd.Context())
		db, err := gorm.Open(postgres.Open(cfg.DB.DSN), &gorm.Config{})
		if err != nil {
			logrus.Fatal(err)
		}

		m := gormigrate.New(db, gormigrate.DefaultOptions, migrations.All())

		if err = m.RollbackLast(); err != nil {
			logrus.Fatalf("Could not rollback: %v", err)
		}
		fmt.Println("Rollback run successfully")
	},
}

func init() {
	migrateCmd.AddCommand(migrateUpCmd)
	migrateCmd.AddCommand(migrateDownCmd)
	rootCmd.AddCommand(migrateCmd)
}
