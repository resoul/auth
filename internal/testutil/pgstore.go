package testutil

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"airlance.org/auth/internal/adapter/id"
	"airlance.org/auth/internal/adapter/postgres"
)

// PostgresStore opens a store on a fresh, migrated schema of the test database, and drops the schema at cleanup.
// It is for tests that need real row locks and real READ COMMITTED: the in-memory store runs one transaction at a
// time, so it cannot show a race. The database is the one `make up` starts; the URL is in
// AIRLANCE_AUTH_TEST_DATABASE_URL.
func PostgresStore(t *testing.T) *postgres.Store {
	t.Helper()
	dsn := os.Getenv("AIRLANCE_AUTH_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("AIRLANCE_AUTH_TEST_DATABASE_URL is not set; run `make up` and `make test-int`")
	}
	admin, err := postgres.OpenMigrationDB(dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("test_%d_%d", time.Now().UnixNano(), os.Getpid())
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)
		_ = admin.Close()
	})

	db, err := postgres.OpenSchemaMigrationDB(dsn, schema)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := postgres.MigrateUp(context.Background(), db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	_ = db.Close()

	store, err := postgres.Open(context.Background(), dsn, id.Generator{}, postgres.WithSchema(schema), postgres.WithMaxConns(8))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	return store
}
