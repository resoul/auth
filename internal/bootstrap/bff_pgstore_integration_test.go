//go:build integration

package bootstrap_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"airlance.org/auth/examples/bff"
	"airlance.org/auth/examples/bff/pgstore"
	"airlance.org/auth/examples/resourcecheck"
	"airlance.org/auth/internal/bootstrap"
)

// bffStorePool opens a pool on a schema of its own, with the store's tables in it.
func bffStorePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AIRLANCE_AUTH_TEST_DATABASE_URL")
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("bff_store_%d_%d", time.Now().UnixNano(), os.Getpid())
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(ctx, `DROP SCHEMA `+schema+` CASCADE`)
		admin.Close()
	})
	if err := pgstore.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return pool
}

// TestBFFInstancesShareOneStore runs the same application twice behind one address, with a PostgreSQL store: a request may
// land on either, and a restart loses nobody.
func TestBFFInstancesShareOneStore(t *testing.T) {
	o := newOIDCService(t)
	o.operate(t, bootstrap.OIDCResourceRequest{Action: bootstrap.OIDCResourceRegister, ID: "platform-api", Name: "Platform", URI: platformResource,
		Audience: "platform-api", Scopes: []string{"messages:read", "messages:send"}})
	check, err := resourcecheck.New(resourcecheck.Config{Issuer: oidcIssuer, Audience: "platform-api", JWKSURL: o.base + "/oauth2/jwks"})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	api := httptest.NewServer(check.Require("messages:send")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte("ok"))
	})))
	t.Cleanup(api.Close)
	upstream, _ := url.Parse(api.URL)

	pool := bffStorePool(t)
	var mu sync.RWMutex
	var instances []http.Handler
	var next atomic.Uint32
	front := &bffApp{logs: &bytes.Buffer{}}
	front.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.RLock()
		h := instances[int(next.Add(1))%len(instances)]
		mu.RUnlock()
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(front.srv.Close)
	secret := o.registerWith(t, bootstrap.OIDCClientRequest{
		ID: "bff-shared", Name: "bff-shared", RedirectURIs: []string{front.srv.URL + "/auth/callback"},
		PostLogoutURIs: []string{front.srv.URL + "/logged-out"}, BackchannelURI: front.srv.URL + "/auth/backchannel-logout",
	})
	o.operate(t, bootstrap.OIDCResourceRequest{Action: bootstrap.OIDCResourceAllow, ID: "platform-api", ClientID: "bff-shared", Scopes: []string{"messages:read", "messages:send"}})
	base, _ := url.Parse(o.base)

	// start builds one instance: its own App and Vault, the shared store.
	start := func() http.Handler {
		vault, err := bff.NewVault("v1", map[string][]byte{"v1": bytes.Repeat([]byte{9}, 32)})
		if err != nil {
			t.Fatal(err)
		}
		a, err := bff.New(bff.Config{
			Issuer: oidcIssuer, ClientID: "bff-shared", ClientSecret: secret, BaseURL: front.srv.URL, Scopes: []string{"email"},
			Resources: []bff.Resource{{Name: "platform", URI: platformResource, Scopes: []string{"messages:send"}, Upstream: upstream}},
			Store:     pgstore.New(pool, nil), Vault: vault, InsecureCookies: true,
			HTTPClient: &http.Client{Timeout: 10 * time.Second, Transport: reroute{to: base}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return a.Handler()
	}
	instances = []http.Handler{start(), start()}
	jar, _ := cookiejar.New(nil)
	front.client = &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// The sign-in begins on one instance and may end on the other: the transaction is in the store.
	b := newBrowser(t, o.base)
	o.signInBFF(t, b, front, "alice@example.test", true)
	me := func() int { r, _ := front.do(t, http.MethodGet, "/api/me", nil); return r.StatusCode }
	for range 4 {
		if got := me(); got != http.StatusOK {
			t.Fatalf("me = %d", got)
		}
	}

	// Many tabs call the API at the same moment, on both instances, with no token yet: one refresh makes it, the rest find it.
	var wg sync.WaitGroup
	var bad atomic.Int32
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, body := front.do(t, http.MethodGet, "/api/platform/x", nil)
			if r.StatusCode != http.StatusOK || body != "ok" {
				bad.Add(1)
			}
		}()
	}
	wg.Wait()
	if bad.Load() != 0 || calls.Load() != 12 {
		t.Fatalf("%d of 12 concurrent calls failed, API saw %d", bad.Load(), calls.Load())
	}
	// A spent refresh token presented again would have ended the grant; the session still works.
	if r, _ := front.do(t, http.MethodGet, "/api/platform/y", nil); r.StatusCode != http.StatusOK {
		t.Fatalf("a call after the concurrent ones = %d", r.StatusCode)
	}

	// A restart: new instances, same store. The cookie in the browser is still good.
	mu.Lock()
	instances = []http.Handler{start(), start()}
	mu.Unlock()
	if got := me(); got != http.StatusOK {
		t.Fatalf("me after a restart = %d", got)
	}
	if r, _ := front.do(t, http.MethodGet, "/api/platform/z", nil); r.StatusCode != http.StatusOK {
		t.Fatalf("an API call after a restart = %d", r.StatusCode)
	}

	// The person takes the application back: the provider's notice lands on one instance, and every instance forgets the session.
	page := b.page()
	_, listBody := page.call(http.MethodGet, "/v1/me/apps", "", o.lastAccess)
	var list struct {
		Apps []struct {
			GrantID string `json:"grant_id"`
		} `json:"apps"`
	}
	if err := json.Unmarshal([]byte(listBody), &list); err != nil || len(list.Apps) != 1 {
		t.Fatalf("list = %s, %v", listBody, err)
	}
	if r, body := page.call(http.MethodDelete, "/v1/me/apps/grants/"+list.Apps[0].GrantID, "", o.lastAccess); r.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke = %d %s", r.StatusCode, body)
	}
	waitUntil(t, "the notice to end the session on every instance", func() bool {
		for range 6 {
			if me() != http.StatusUnauthorized {
				return false
			}
		}
		return true
	})
}
