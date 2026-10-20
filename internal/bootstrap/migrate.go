package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"go.airlance.org/auth/internal/adapter/postgres"
	"go.airlance.org/auth/internal/config"
)

// MigrateAction selects what the migrate command does.
type MigrateAction string

// Migrate actions.
const (
	MigrateUp     MigrateAction = "up"
	MigrateDown   MigrateAction = "down"
	MigrateStatus MigrateAction = "status"
)

// Migrate runs a migration action against the configured database and reports to out.
func Migrate(ctx context.Context, cfg config.Config, action MigrateAction, out io.Writer) error {
	if !cfg.Database.URL.IsSet() {
		return fmt.Errorf("%s is required for migrate", config.EnvDatabaseURL)
	}

	db, err := postgres.OpenSchemaMigrationDB(cfg.Database.URL.Reveal(), cfg.Database.Schema)
	if err != nil {
		return err
	}

	defer func() { _ = db.Close() }()
	// Only up creates the schema: down and status must not invent an empty one.
	if action == MigrateUp && cfg.Database.Schema != "" {
		if err := postgres.EnsureSchema(ctx, db, cfg.Database.Schema); err != nil {
			return err
		}
	}

	switch action {
	case MigrateUp:
		steps, err := postgres.MigrateUp(ctx, db)
		if err != nil {
			return err
		}

		if len(steps) == 0 {
			_, err = fmt.Fprintln(out, "no pending migrations")
			return err
		}

		for _, s := range steps {
			if _, err := fmt.Fprintf(out, "applied %s\n", s.Name); err != nil {
				return err
			}
		}

		return nil
	case MigrateDown:
		step, rolledBack, err := postgres.MigrateDown(ctx, db)
		if err != nil {
			return err
		}

		if !rolledBack {
			_, err = fmt.Fprintln(out, "nothing to roll back")
			return err
		}

		_, err = fmt.Fprintf(out, "rolled back %s\n", step.Name)

		return err
	case MigrateStatus:
		steps, err := postgres.MigrationStatus(ctx, db)
		if err != nil {
			return err
		}

		for _, s := range steps {
			state := "pending"
			if !s.AppliedAt.IsZero() {
				state = "applied " + s.AppliedAt.UTC().Format(time.RFC3339)
			}

			if _, err := fmt.Fprintf(out, "%s\t%s\n", s.Name, state); err != nil {
				return err
			}
		}

		return nil
	}

	return errors.New("unknown migrate action")
}
