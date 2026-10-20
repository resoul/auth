package bootstrap_test

import (
	"bytes"
	"strings"
	"testing"

	"go.airlance.org/auth/internal/bootstrap"
	"go.airlance.org/auth/internal/config"
)

func TestMigrateRequiresDatabaseURL(t *testing.T) {
	var out bytes.Buffer
	for _, action := range []bootstrap.MigrateAction{bootstrap.MigrateUp, bootstrap.MigrateDown, bootstrap.MigrateStatus} {
		err := bootstrap.Migrate(t.Context(), config.Config{}, action, &out)
		if err == nil || !strings.Contains(err.Error(), config.EnvDatabaseURL) {
			t.Errorf("%s: error = %v, want a request for %s", action, err, config.EnvDatabaseURL)
		}
	}
}

func TestMigrateRejectsUnknownAction(t *testing.T) {
	cfg := config.Config{Database: config.DatabaseConfig{URL: config.NewSecret("postgres://u:p@127.0.0.1:1/db")}}
	if err := bootstrap.Migrate(t.Context(), cfg, "sideways", &bytes.Buffer{}); err == nil {
		t.Error("unknown action accepted")
	}
}
