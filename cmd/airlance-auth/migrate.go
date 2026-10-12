package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"airlance.org/auth/internal/bootstrap"
	"airlance.org/auth/internal/config"
)

func newMigrateCommand() *cobra.Command {
	migrate := &cobra.Command{
		Use:   "migrate",
		Short: "Manage the database schema (needs AIRLANCE_AUTH_DATABASE_URL)",
	}
	for _, sub := range []struct {
		action bootstrap.MigrateAction
		short  string
	}{
		{bootstrap.MigrateUp, "Apply all pending migrations"},
		{bootstrap.MigrateDown, "Roll back the latest migration"},
		{bootstrap.MigrateStatus, "List migrations and whether they are applied"},
	} {
		migrate.AddCommand(&cobra.Command{
			Use:   string(sub.action),
			Short: sub.short,
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				cfg, err := config.Load(os.LookupEnv)
				if err != nil {
					return err
				}
				ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
				defer stop()
				return bootstrap.Migrate(ctx, cfg, sub.action, cmd.OutOrStdout())
			},
		})
	}
	return migrate
}
