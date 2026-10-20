//go:build integration

package oidc_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"go.airlance.org/auth/internal/adapter/postgres"
	appoidc "go.airlance.org/auth/internal/application/oidc"
	"go.airlance.org/auth/internal/application/port"
	doidc "go.airlance.org/auth/internal/domain/oidc"
)

func TestStartingASignInIsLimitedPerAddressButTheSharedSignInIsNot(t *testing.T) {
	e := newEnv(t)
	app := e.register("panels-web", appCallback, "openid", "email")
	alice := e.newPerson()
	_, sso := e.signedIn(e.newFlow(app), alice) // counts as one start from an unknown address
	here, elsewhere := netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("203.0.113.9")

	start := func(ip netip.Addr, sso string) appoidc.AuthorizeResult {
		cmd := e.newFlow(app).command(sso)
		cmd.ClientIP = ip

		return e.authorizeWith(cmd)
	}
	for i := range 60 {
		if got := start(here, ""); got.Kind != appoidc.AuthorizeLogin {
			t.Fatalf("start %d = %+v, want the sign-in page", i+1, got)
		}
	}

	got := start(here, "")
	if got.Kind != appoidc.AuthorizeRedirect || got.Location == "" || !contains(got.Location, "error=temporarily_unavailable") {
		t.Errorf("the 61st start in a minute = %+v, want temporarily_unavailable back to the application", got)
	}
	// Another address has its own budget.
	if got := start(elsewhere, ""); got.Kind != appoidc.AuthorizeLogin {
		t.Errorf("another address = %+v", got)
	}
	// An authorization that finds the shared sign-in writes no request row and spends nothing.
	for range 100 {
		if got := start(here, sso); got.Kind != appoidc.AuthorizeRedirect || contains(got.Location, "error=") {
			t.Fatalf("with the shared sign-in = %+v, want a code", got)
		}
	}
	// The window moves on.
	e.clock.Advance(2 * time.Minute)

	if got := start(here, ""); got.Kind != appoidc.AuthorizeLogin {
		t.Errorf("after the window = %+v", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}

	return false
}

func TestCleanupRemovesWhatExpiredAndKeepsWhatLives(t *testing.T) {
	e := newEnv(t)
	app := e.register("panels-web", appCallback, "openid", "email")
	alice := e.newPerson()
	live := e.newFlow(app)
	liveCode, liveSSO := e.signedIn(live, alice)

	// A request that nobody completed, and a code nobody exchanged.
	abandoned := e.authorizeWith(e.newFlow(app).command(""))
	spent := e.newFlow(app)
	spentCode, spentSSO := e.signedIn(spent, e.newPerson())

	e.clock.Advance(15 * 24 * time.Hour) // past the absolute time of the sign-ins (7 days) and their grace period (7 more)

	res, err := e.store.Cleanup(context.Background(), e.clock.Now(), postgres.DefaultCleanupPolicy())
	if err != nil {
		t.Fatal(err)
	}

	if res.OIDCRows == 0 {
		t.Fatalf("cleanup removed no OIDC rows: %+v", res)
	}

	h := func(secret string) doidc.SecretHash {
		hash, err := e.secrets.HashOIDCSecret(secret)
		must(t, err)

		return hash
	}

	e.do(func(ctx context.Context, st port.Stores) error {
		if _, err := st.OIDCRequests.GetForUpdate(ctx, h(abandoned.RequestID)); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("an abandoned request survived: %v", err)
		}

		for name, code := range map[string]string{"first": liveCode, "second": spentCode} {
			if _, _, err := st.OIDCCodes.GetByHashForUpdate(ctx, h(code)); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("the %s code survived: %v", name, err)
			}
		}

		for name, sso := range map[string]string{"first": liveSSO, "second": spentSSO} {
			if _, err := st.OPSessions.GetBySecret(ctx, h(sso)); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("the %s ended sign-in survived: %v", name, err)
			}
		}
		// The client is not a short-lived row.
		if _, err := st.OIDCClients.Get(ctx, app.id); err != nil {
			t.Errorf("cleanup removed the client: %v", err)
		}

		return nil
	})
}

func TestCleanupKeepsALiveSignInAndItsGrant(t *testing.T) {
	e := newEnv(t)
	app := e.register("panels-web", appCallback, "openid", "email")
	tokens, sso := e.tokens(e.newFlow(app), e.newPerson())

	e.clock.Advance(time.Hour)

	if _, err := e.store.Cleanup(context.Background(), e.clock.Now(), postgres.DefaultCleanupPolicy()); err != nil {
		t.Fatal(err)
	}

	if got := e.refresh(app, tokens.RefreshToken); got.Response == nil {
		t.Errorf("cleanup broke a live grant: %+v", got.Failure)
	}

	if got := e.authorizeWith(e.newFlow(app).command(sso)); got.Kind != appoidc.AuthorizeRedirect {
		t.Errorf("cleanup ended a live sign-in: %+v", got)
	}
}
