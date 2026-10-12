package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	// database/sql handle for migrations only; repositories use pgxpool.
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"airlance.org/auth/migrations"
)

// MigrationStep describes one migration for callers outside this package.
type MigrationStep struct {
	Version int64
	Name    string
	// AppliedAt is the zero time while the migration is pending.
	AppliedAt time.Time
}

// VersionTable is the table that records the applied migrations. It has its own name, not goose's
// default, so a service that shares a schema and also uses goose cannot read or overwrite it.
const VersionTable = "auth_schema_version"

// OpenMigrationDB opens a short-lived database/sql handle for the migrate command, in the
// search_path of the connection string. It does not connect until first use. Error messages
// never contain the DSN.
func OpenMigrationDB(dsn string) (*sql.DB, error) {
	return OpenSchemaMigrationDB(dsn, "")
}

// OpenSchemaMigrationDB is OpenMigrationDB with the search_path set to schema, which takes
// precedence over one in the connection string. An empty schema changes nothing.
func OpenSchemaMigrationDB(dsn, schema string) (*sql.DB, error) {
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, errors.New("open database: invalid connection string")
	}
	if schema != "" {
		if err := ValidateSchemaName(schema); err != nil {
			return nil, err
		}
		cfg.RuntimeParams["search_path"] = schema
	}
	return stdlib.OpenDB(*cfg), nil
}

// EnsureSchema creates the schema when it does not exist, so the migrations and the version
// table land in it and not in whatever schema comes first in the role's search_path.
func EnsureSchema(ctx context.Context, db *sql.DB, schema string) error {
	if err := ValidateSchemaName(schema); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, "CREATE SCHEMA IF NOT EXISTS "+pgx.Identifier{schema}.Sanitize()); err != nil {
		return fmt.Errorf("create schema %q: %w", schema, err)
	}
	return nil
}

func newProvider(db *sql.DB) (*goose.Provider, error) {
	locker, err := lock.NewPostgresSessionLocker(lock.WithLockTimeout(1, 60))
	if err != nil {
		return nil, fmt.Errorf("create migration lock: %w", err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS, goose.WithSessionLocker(locker), goose.WithTableName(VersionTable))
	if err != nil {
		return nil, fmt.Errorf("create migration provider: %w", err)
	}
	return provider, nil
}

// MigrateUp applies all pending migrations and returns the ones it applied.
func MigrateUp(ctx context.Context, db *sql.DB) ([]MigrationStep, error) {
	if err := adoptLegacyVersionTable(ctx, db); err != nil {
		return nil, err
	}
	provider, err := newProvider(db)
	if err != nil {
		return nil, err
	}
	results, err := provider.Up(ctx)
	if err != nil {
		return nil, fmt.Errorf("migrate up: %w", err)
	}
	steps := make([]MigrationStep, 0, len(results))
	for _, r := range results {
		steps = append(steps, MigrationStep{Version: r.Source.Version, Name: r.Source.Path, AppliedAt: time.Now()})
	}
	return steps, nil
}

// MigrateDown rolls back the most recently applied migration. It returns false
// when there was nothing to roll back.
func MigrateDown(ctx context.Context, db *sql.DB) (MigrationStep, bool, error) {
	if err := adoptLegacyVersionTable(ctx, db); err != nil {
		return MigrationStep{}, false, err
	}
	provider, err := newProvider(db)
	if err != nil {
		return MigrationStep{}, false, err
	}
	result, err := provider.Down(ctx)
	if errors.Is(err, goose.ErrNoNextVersion) {
		return MigrationStep{}, false, nil
	}
	if err != nil {
		return MigrationStep{}, false, fmt.Errorf("migrate down: %w", err)
	}
	return MigrationStep{Version: result.Source.Version, Name: result.Source.Path}, true, nil
}

// MigrationStatus lists every known migration with its applied time.
func MigrationStatus(ctx context.Context, db *sql.DB) ([]MigrationStep, error) {
	if err := adoptLegacyVersionTable(ctx, db); err != nil {
		return nil, err
	}
	provider, err := newProvider(db)
	if err != nil {
		return nil, err
	}
	statuses, err := provider.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("migration status: %w", err)
	}
	steps := make([]MigrationStep, 0, len(statuses))
	for _, s := range statuses {
		step := MigrationStep{Version: s.Source.Version, Name: s.Source.Path}
		if s.State == goose.StateApplied {
			step.AppliedAt = s.AppliedAt
		}
		steps = append(steps, step)
	}
	return steps, nil
}

// KnownMigrations lists the embedded migrations without touching a database.
func KnownMigrations() ([]MigrationStep, error) {
	db, err := OpenMigrationDB("postgres://unused@localhost/unused")
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	provider, err := newProvider(db)
	if err != nil {
		return nil, err
	}
	var steps []MigrationStep
	for _, s := range provider.ListSources() {
		steps = append(steps, MigrationStep{Version: s.Version, Name: s.Path})
	}
	return steps, nil
}
