//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"go.airlance.org/auth/internal/adapter/id"
	"go.airlance.org/auth/internal/adapter/postgres"
)

// ownSchema returns a schema name that does not exist yet and is dropped at cleanup.
func ownSchema(t *testing.T) (admin *sql.DB, schema string) {
	t.Helper()

	base := os.Getenv("AIRLANCE_AUTH_TEST_DATABASE_URL")
	if base == "" {
		t.Fatal("AIRLANCE_AUTH_TEST_DATABASE_URL is not set; run `make up` and `make test-int`")
	}

	admin = openDB(t, base)
	schema = fmt.Sprintf("test_%d_%d", time.Now().UnixNano(), os.Getpid())

	t.Cleanup(func() { _, _ = admin.Exec(`DROP SCHEMA IF EXISTS ` + schema + ` CASCADE`) })

	return admin, schema
}

func inSchema(t *testing.T, schema string) *sql.DB {
	t.Helper()

	db, err := postgres.OpenSchemaMigrationDB(os.Getenv("AIRLANCE_AUTH_TEST_DATABASE_URL"), schema)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = db.Close() })

	return db
}

func qualifiedExists(t *testing.T, db *sql.DB, schema, table string) bool {
	t.Helper()

	var ok bool
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = $1 AND tablename = $2)`, schema, table).Scan(&ok); err != nil {
		t.Fatal(err)
	}

	return ok
}

func TestMigrateCreatesTheSchemaAndKeepsEverythingInIt(t *testing.T) {
	ctx := context.Background()
	admin, schema := ownSchema(t)
	db := inSchema(t, schema)

	if err := postgres.EnsureSchema(ctx, db, schema); err != nil {
		t.Fatal(err)
	}

	if _, err := postgres.MigrateUp(ctx, db); err != nil {
		t.Fatal(err)
	}

	for _, table := range append([]string{postgres.VersionTable}, tables...) {
		if !qualifiedExists(t, admin, schema, table) {
			t.Errorf("%s.%s is missing", schema, table)
		}
	}
	// Goose's default table is not ours to create: another service may own it.
	if qualifiedExists(t, admin, schema, "goose_db_version") {
		t.Error("the default goose table was created")
	}
}

func TestStoreUsesTheConfiguredSchema(t *testing.T) {
	ctx := context.Background()
	admin, schema := ownSchema(t)

	db := inSchema(t, schema)
	if err := postgres.EnsureSchema(ctx, db, schema); err != nil {
		t.Fatal(err)
	}

	if _, err := postgres.MigrateUp(ctx, db); err != nil {
		t.Fatal(err)
	}

	store, err := postgres.Open(ctx, os.Getenv("AIRLANCE_AUTH_TEST_DATABASE_URL"), id.Generator{}, postgres.WithSchema(schema), postgres.WithMaxConns(2))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	// The pool sees the tables without qualification, so every repository query finds them.
	if err := store.Ping(ctx); err != nil {
		t.Fatal(err)
	}

	exec(t, admin, fmt.Sprintf(`INSERT INTO %s.users (id, email, email_verified_at, created_at, updated_at) VALUES ($1, 'a@example.com', now(), now(), now())`, schema), userID)
}

func TestMigrateAdoptsTheHistoryOfEarlierReleases(t *testing.T) {
	ctx := context.Background()
	_, schema := ownSchema(t)

	db := inSchema(t, schema)
	if err := postgres.EnsureSchema(ctx, db, schema); err != nil {
		t.Fatal(err)
	}

	if _, err := postgres.MigrateUp(ctx, db); err != nil {
		t.Fatal(err)
	}
	// Recreate the state an earlier release left: the history is in goose's default table.
	exec(t, db, `ALTER TABLE `+postgres.VersionTable+` RENAME TO goose_db_version`)

	steps, err := postgres.MigrateUp(ctx, db)
	if err != nil || len(steps) != 0 {
		t.Fatalf("MigrateUp over an adopted history = %+v, %v; want a no-op", steps, err)
	}

	if !tableExists(t, db, postgres.VersionTable) || !tableExists(t, db, "goose_db_version") {
		t.Error("want the new table created and the old one left in place")
	}

	status, err := postgres.MigrationStatus(ctx, db)
	if err != nil {
		t.Fatal(err)
	}

	for _, s := range status {
		if s.AppliedAt.IsZero() {
			t.Errorf("%s is pending after adoption", s.Name)
		}
	}
}

func TestMigrateLeavesAForeignGooseTableAlone(t *testing.T) {
	ctx := context.Background()
	_, schema := ownSchema(t)

	db := inSchema(t, schema)
	if err := postgres.EnsureSchema(ctx, db, schema); err != nil {
		t.Fatal(err)
	}
	// Another service's history, in a shared schema, with none of our tables.
	exec(t, db, `CREATE TABLE goose_db_version (id serial PRIMARY KEY, version_id bigint NOT NULL, is_applied boolean NOT NULL, tstamp timestamp NOT NULL DEFAULT now())`)
	exec(t, db, `INSERT INTO goose_db_version (version_id, is_applied) VALUES (0, true), (1, true), (2, true)`)

	steps, err := postgres.MigrateUp(ctx, db)
	if err != nil {
		t.Fatal(err)
	}

	known, _ := postgres.KnownMigrations()
	if len(steps) != len(known) {
		t.Fatalf("applied %d migrations, want all %d: the foreign history must not count", len(steps), len(known))
	}
}

func TestSchemaNamesAreValidated(t *testing.T) {
	for _, bad := range []string{"Auth", "a b", "a,b", `a"b`, "1abc", "pg_catalog", "a;drop"} {
		if err := postgres.ValidateSchemaName(bad); err == nil {
			t.Errorf("ValidateSchemaName(%q) accepted the name", bad)
		}

		if _, err := postgres.OpenSchemaMigrationDB("postgres://u@h/db", bad); err == nil {
			t.Errorf("OpenSchemaMigrationDB accepted %q", bad)
		}
	}

	if err := postgres.ValidateSchemaName("auth"); err != nil {
		t.Error(err)
	}
}
