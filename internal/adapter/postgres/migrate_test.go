package postgres_test

import (
	"io/fs"
	"strings"
	"testing"

	"go.airlance.org/auth/internal/adapter/postgres"
	"go.airlance.org/auth/migrations"
)

func TestKnownMigrationsAreOrderedAndStartAtOne(t *testing.T) {
	steps, err := postgres.KnownMigrations()
	if err != nil {
		t.Fatalf("KnownMigrations: %v", err)
	}

	if len(steps) == 0 || steps[0].Version != 1 {
		t.Fatalf("steps = %+v, want versions starting at 1", steps)
	}

	for i := 1; i < len(steps); i++ {
		if steps[i].Version != steps[i-1].Version+1 {
			t.Errorf("gap between versions %d and %d", steps[i-1].Version, steps[i].Version)
		}
	}
}

func TestEveryMigrationCanBeRolledBack(t *testing.T) {
	files, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil || len(files) == 0 {
		t.Fatalf("no migrations embedded: %v", err)
	}

	for _, name := range files {
		data, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			t.Fatal(err)
		}

		text := string(data)

		up, down := strings.Index(text, "-- +goose Up"), strings.Index(text, "-- +goose Down")
		if up < 0 || down < up || strings.TrimSpace(text[down+len("-- +goose Down"):]) == "" {
			t.Errorf("%s needs an Up section followed by a non-empty Down section", name)
		}
	}
}

func TestOpenMigrationDBDoesNotLeakTheConnectionString(t *testing.T) {
	_, err := postgres.OpenMigrationDB("not a url\x00 hunter2")
	if err != nil && strings.Contains(err.Error(), "hunter2") {
		t.Errorf("error %q echoes the DSN", err)
	}
}
