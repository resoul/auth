package bootstrap_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"go.airlance.org/auth/internal/bootstrap"
	"go.airlance.org/auth/internal/config"
)

func TestInviteRequiresTheDatabaseBeforeAnythingElse(t *testing.T) {
	for _, action := range []bootstrap.InviteAction{bootstrap.InviteCreate, bootstrap.InviteList, bootstrap.InviteRevoke} {
		err := bootstrap.Invite(t.Context(), config.Config{}, bootstrap.InviteRequest{Action: action, Email: "a@example.test", TTL: time.Hour}, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), config.EnvDatabaseURL) {
			t.Errorf("%s: error = %v, want a request for %s", action, err, config.EnvDatabaseURL)
		}
	}
}

func TestInviteRefusesABadAddressWithoutOpeningTheDatabase(t *testing.T) {
	cfg := config.Config{Database: config.DatabaseConfig{URL: config.NewSecret("postgres://u:p@127.0.0.1:1/db")}}

	for _, action := range []bootstrap.InviteAction{bootstrap.InviteCreate, bootstrap.InviteRevoke} {
		for _, bad := range []string{"", "not an address", "two@@example.test", "a b@example.test"} {
			err := bootstrap.Invite(t.Context(), cfg, bootstrap.InviteRequest{Action: action, Email: bad, TTL: time.Hour}, &bytes.Buffer{})
			if err == nil || strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), "u:p") {
				t.Errorf("%s %q: error = %v", action, bad, err)
			}
		}
	}
}
