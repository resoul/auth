//go:build integration

package bootstrap_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"airlance.org/auth/examples/resourcecheck"
	"airlance.org/auth/internal/bootstrap"
)

func TestAServiceCallsAnAPIWithoutAUserOnTheRealService(t *testing.T) {
	o := newOIDCService(t)
	o.operate(t, bootstrap.OIDCResourceRequest{Action: bootstrap.OIDCResourceRegister, ID: "platform-api", Name: "Platform", URI: platformResource,
		Audience: "platform-api", Scopes: []string{"messages:read", "messages:send"}})
	apiSecret := secretOf(t, o.operate(t, bootstrap.OIDCResourceRequest{Action: bootstrap.OIDCResourceRotate, ID: "platform-api", Overlap: time.Hour}))

	// The operator registers a service on the server: no redirect URI, no scopes, and nothing it may call until allowed.
	var out strings.Builder
	if err := bootstrap.OIDCClient(context.Background(), o.cfg, bootstrap.OIDCClientRequest{Action: bootstrap.OIDCClientCreate, ID: "billing-worker", Name: "Billing", Service: true}, &writer{&out}); err != nil {
		t.Fatal(err)
	}
	m := secretLine.FindStringSubmatch(out.String())
	if m == nil || !strings.Contains(out.String(), "registered service") {
		t.Fatalf("the command printed %q", out.String())
	}
	secret := m[1]
	var listed strings.Builder
	if err := bootstrap.OIDCClient(context.Background(), o.cfg, bootstrap.OIDCClientRequest{Action: bootstrap.OIDCClientList}, &writer{&listed}); err != nil || !strings.Contains(listed.String(), "billing-worker\tactive\tservice") {
		t.Errorf("list = %q, %v", listed.String(), err)
	}

	token := func(user, pass string, form url.Values) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, o.base+"/oauth2/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(url.QueryEscape(user), url.QueryEscape(pass))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		data, _ := io.ReadAll(resp.Body)
		var body map[string]any
		_ = json.Unmarshal(data, &body)
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("a token response may be cached: %q", resp.Header.Get("Cache-Control"))
		}
		return resp.StatusCode, body
	}
	form := url.Values{"grant_type": {"client_credentials"}, "resource": {platformResource}}

	// Nothing allowed yet: the service asks and is told the resource is not its.
	if status, body := token("billing-worker", secret, form); status != http.StatusBadRequest || body["error"] != "invalid_target" {
		t.Fatalf("before it was allowed = %d %v", status, body)
	}
	o.operate(t, bootstrap.OIDCResourceRequest{Action: bootstrap.OIDCResourceAllow, ID: "platform-api", ClientID: "billing-worker", Scopes: []string{"messages:send"}})
	status, body := token("billing-worker", secret, form)
	if status != http.StatusOK || body["token_type"] != "Bearer" || body["scope"] != "messages:send" || body["refresh_token"] != nil || body["id_token"] != nil || body["access_token"] == nil {
		t.Fatalf("token = %d %v", status, body)
	}
	access := body["access_token"].(string)
	if c := verifiedIDToken(t, o.base, access); c["aud"] != "platform-api" || c["sub"] != "billing-worker" || c["client_id"] != "billing-worker" || c["sid"] != nil || c["grant_id"] != nil || c["scope"] != "messages:send" {
		t.Errorf("claims = %v", c)
	}
	if status, body := token("billing-worker", "wrong", form); status != http.StatusUnauthorized || body["error"] != "invalid_client" {
		t.Errorf("wrong secret = %d %v", status, body)
	}
	if status, body := token("billing-worker", secret, url.Values{"grant_type": {"client_credentials"}}); status != http.StatusBadRequest || body["error"] != "invalid_target" {
		t.Errorf("no resource = %d %v", status, body)
	}
	if status, body := token("billing-worker", secret, url.Values{"grant_type": {"client_credentials"}, "resource": {platformResource, "https://x.example.test/"}}); status != http.StatusBadRequest || body["error"] != "invalid_target" {
		t.Errorf("two resources = %d %v", status, body)
	}
	if status, body := token("billing-worker", secret, url.Values{"grant_type": {"authorization_code"}, "code": {"x"}}); status != http.StatusBadRequest || body["error"] != "unauthorized_client" {
		t.Errorf("a service with a code = %d %v", status, body)
	}

	// An API of its own, checking with the package a service would copy, and asking the issuer about every token.
	check, err := resourcecheck.New(resourcecheck.Config{
		Issuer: oidcIssuer, Audience: "platform-api", JWKSURL: o.base + "/oauth2/jwks",
		Introspection: &resourcecheck.Introspection{URL: o.base + "/oauth2/introspect", ResourceID: "platform-api", Secret: apiSecret},
	})
	if err != nil {
		t.Fatal(err)
	}
	var sawService bool
	handler := func(w http.ResponseWriter, r *http.Request) {
		c, _ := resourcecheck.FromContext(r.Context())
		sawService = c.Service && c.Subject == "billing-worker"
		w.WriteHeader(http.StatusNoContent)
	}
	anyCaller := httptest.NewServer(check.Require("messages:send")(http.HandlerFunc(handler)))
	peopleOnly := httptest.NewServer(check.RequireUser("messages:send")(http.HandlerFunc(handler)))
	t.Cleanup(anyCaller.Close)
	t.Cleanup(peopleOnly.Close)
	call := func(srv *httptest.Server, token string) int {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, srv.URL, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if got := call(anyCaller, access); got != http.StatusNoContent || !sawService {
		t.Fatalf("the API's answer to a service = %d (saw a service: %v)", got, sawService)
	}
	if got := call(peopleOnly, access); got != http.StatusForbidden {
		t.Errorf("an API for people took a service: %d", got)
	}

	// The operator takes the right away: the token is good for minutes by its signature, and the API is told at once.
	o.operate(t, bootstrap.OIDCResourceRequest{Action: bootstrap.OIDCResourceDeny, ID: "platform-api", ClientID: "billing-worker"})
	if got := call(anyCaller, access); got != http.StatusUnauthorized {
		t.Errorf("after the right was taken = %d", got)
	}
	if status, body := token("billing-worker", secret, form); status != http.StatusBadRequest || body["error"] != "invalid_target" {
		t.Errorf("a new token after the right was taken = %d %v", status, body)
	}
}

// writer adapts a strings.Builder to io.Writer for the commands that print.
type writer struct{ b *strings.Builder }

func (w *writer) Write(p []byte) (int, error) { return w.b.Write(p) }
