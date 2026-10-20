package oidc_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"go.airlance.org/auth/internal/adapter/crypto"
	"go.airlance.org/auth/internal/adapter/jwt"
	"go.airlance.org/auth/internal/adapter/memory"
	appoidc "go.airlance.org/auth/internal/application/oidc"
	"go.airlance.org/auth/internal/application/port"
	doidc "go.airlance.org/auth/internal/domain/oidc"
	"go.airlance.org/auth/internal/testutil"
	oidcapi "go.airlance.org/auth/internal/transport/http/oidc"
)

// These tests hold the HTTP contract of the provider: methods, forms, repeated parameters, client authentication,
// error bodies, cookies and caching. They run the real use cases on the in-memory store, so they are fast; the
// flows end to end, with their transactions, are in the integration tests of internal/bootstrap.

const (
	issuer      = "https://auth.example.test"
	clientID    = "example-web"
	redirectURI = "https://app.example.test/callback"
)

type provider struct {
	t      *testing.T
	mux    *http.ServeMux
	secret string
}

// newProvider runs the provider on the in-memory store, which holds no client: what is checked before a client is
// looked up. newProviderOn runs it on another store and registers a client there.
func newProvider(t *testing.T) *provider {
	t.Helper()

	return newProviderOn(t, memory.NewStore(), false)
}

func newProviderOn(t *testing.T, store port.UnitOfWork, register bool) *provider {
	t.Helper()

	factory := testutil.NewFactory(t, time.Now())

	ecPEM := testutil.NewSigningKeyPEM(t)
	ec, err := jwt.LoadRing("sign-a", map[string]string{"sign-a": testutil.WriteFile(t, "a.pem", ecPEM.Private)})
	must(t, err)
	access, err := jwt.NewVerifier(ec.PublicKeys(), factory.Clock, issuer, "example", 30*time.Second)
	must(t, err)

	rsaPEM := testutil.NewRSAKeyPEM(t)
	ring, err := jwt.LoadRSARing("oidc-a", map[string]string{"oidc-a": testutil.WriteFile(t, "oidc.pem", rsaPEM.Private)})
	must(t, err)
	tokens, err := jwt.NewOIDCTokens(ring, factory.Clock, issuer, 5*time.Minute, 5*time.Minute, 30*time.Second)
	must(t, err)

	deps := appoidc.Deps{
		UnitOfWork: store, Clock: factory.Clock, Secrets: crypto.OIDC{}, IDs: factory.IDs, Signer: tokens, Verifier: tokens,
		Issuer: issuer, Policy: doidc.DefaultPolicy(),
	}
	authorize, err := appoidc.NewAuthorize(deps)
	must(t, err)
	login, err := appoidc.NewCompleteLogin(deps, access)
	must(t, err)
	token, err := appoidc.NewToken(deps)
	must(t, err)
	userinfo, err := appoidc.NewUserInfo(deps)
	must(t, err)
	logout, err := appoidc.NewLogout(deps)
	must(t, err)
	revoke, err := appoidc.NewRevoke(deps)
	must(t, err)
	introspect, err := appoidc.NewIntrospect(deps)
	must(t, err)
	clients, err := appoidc.NewClients(deps)
	must(t, err)

	handler, err := oidcapi.New(oidcapi.Deps{
		Issuer: issuer, Policy: deps.Policy, Authorize: authorize, Login: login, Token: token, UserInfo: userinfo, Logout: logout,
		Revoke: revoke, Introspect: introspect, JWKS: ring, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Clock: factory.Clock,
	})
	must(t, err)

	// Without a stored client the secret only has to look like one: the requests these tests make are refused first.
	secret := "not-a-registered-secret"

	if register {
		registered, err := clients.Register(context.Background(), appoidc.RegisterCommand{
			ID: clientID, Name: "Example", RedirectURIs: []string{redirectURI}, AllowedScopes: doidc.SupportedScopes(),
		})
		must(t, err)

		secret = registered.Secret
	}

	mux := http.NewServeMux()
	handler.Routes(mux)

	return &provider{t: t, mux: mux, secret: secret}
}

func must(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatal(err)
	}
}

func (p *provider) do(r *http.Request) *httptest.ResponseRecorder {
	p.t.Helper()

	w := httptest.NewRecorder()
	p.mux.ServeHTTP(w, r)

	return w
}

// form is a POST with a form body; auth adds the client's HTTP Basic credentials.
func (p *provider) form(path string, values url.Values, auth bool) *http.Request {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if auth {
		r.SetBasicAuth(clientID, p.secret)
	}

	return r
}

// oauthError reads an RFC 6749 error body and checks it is never cached.
func oauthError(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()

	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body %q: %v", w.Body.String(), err)
	}

	if w.Code != status || body["error"] != code || body["error_description"] == "" {
		t.Errorf("response = %d %v, want %d %s", w.Code, body, status, code)
	}

	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Pragma") != "no-cache" {
		t.Errorf("an error of the provider may be cached: %v", w.Header())
	}

	if w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q", w.Header().Get("Content-Type"))
	}
}

func TestDiscoveryAndKeySetArePublicAndCacheable(t *testing.T) {
	p := newProvider(t)

	w := p.do(httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))

	var doc map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil || w.Code != http.StatusOK {
		t.Fatalf("discovery = %d %s, %v", w.Code, w.Body.String(), err)
	}

	for key, want := range map[string]string{
		"issuer": issuer, "token_endpoint": issuer + "/oauth2/token", "jwks_uri": issuer + "/oauth2/jwks",
		"introspection_endpoint": issuer + "/oauth2/introspect", "authorization_endpoint": issuer + "/oauth2/authorize",
	} {
		if doc[key] != want {
			t.Errorf("discovery %s = %v, want %s", key, doc[key], want)
		}
	}

	keys := p.do(httptest.NewRequest(http.MethodGet, "/oauth2/jwks", nil))

	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(keys.Body.Bytes(), &set); err != nil || len(set.Keys) != 1 || set.Keys[0]["kid"] != "oidc-a" || set.Keys[0]["d"] != nil {
		t.Errorf("key set = %s, %v; want the public part of oidc-a only", keys.Body.String(), err)
	}

	for name, r := range map[string]*httptest.ResponseRecorder{"discovery": w, "key set": keys} {
		if r.Header().Get("Cache-Control") != "public, max-age=300" || r.Header().Get("Content-Type") != "application/json" {
			t.Errorf("%s headers = %v", name, r.Header())
		}
	}
}

func TestTheTokenEndpointRefusesMalformedRequests(t *testing.T) {
	p := newProvider(t)
	grant := url.Values{"grant_type": {"authorization_code"}, "code": {"x"}, "redirect_uri": {redirectURI}, "code_verifier": {"v"}}

	t.Run("a body that is not a form", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(`{"grant_type":"authorization_code"}`))
		r.Header.Set("Content-Type", "application/json")
		r.SetBasicAuth(clientID, p.secret)
		oauthError(t, p.do(r), http.StatusBadRequest, "invalid_request")
	})

	t.Run("no client authentication", func(t *testing.T) {
		w := p.do(p.form("/oauth2/token", grant, false))
		oauthError(t, w, http.StatusUnauthorized, "invalid_client")

		if !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "Basic ") {
			t.Errorf("WWW-Authenticate = %q", w.Header().Get("WWW-Authenticate"))
		}
	})

	t.Run("a client secret in the body is not a credential", func(t *testing.T) {
		body := url.Values{"client_id": {clientID}, "client_secret": {p.secret}}
		for k, v := range grant {
			body[k] = v
		}

		oauthError(t, p.do(p.form("/oauth2/token", body, false)), http.StatusUnauthorized, "invalid_client")
	})

	t.Run("a repeated parameter", func(t *testing.T) {
		repeated := url.Values{"grant_type": {"authorization_code", "refresh_token"}}
		oauthError(t, p.do(p.form("/oauth2/token", repeated, true)), http.StatusBadRequest, "invalid_request")
	})

	t.Run("parameters in the query", func(t *testing.T) {
		r := p.form("/oauth2/token?code=x", grant, true)
		oauthError(t, p.do(r), http.StatusBadRequest, "invalid_request")
	})

	t.Run("two resources", func(t *testing.T) {
		two := url.Values{"grant_type": {"client_credentials"}, "resource": {"https://a.example.test", "https://b.example.test"}}
		oauthError(t, p.do(p.form("/oauth2/token", two, true)), http.StatusBadRequest, "invalid_target")
	})

	t.Run("GET", func(t *testing.T) {
		if w := p.do(httptest.NewRequest(http.MethodGet, "/oauth2/token", nil)); w.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET /oauth2/token = %d, want 405", w.Code)
		}
	})
}

func TestRevocationAndIntrospectionNeedTheirCredentials(t *testing.T) {
	p := newProvider(t)

	w := p.do(p.form("/oauth2/revoke", url.Values{"token": {"x"}}, false))
	oauthError(t, w, http.StatusUnauthorized, "invalid_client")

	r := httptest.NewRequest(http.MethodPost, "/oauth2/revoke", strings.NewReader("token=x"))
	r.Header.Set("Content-Type", "text/plain")
	r.SetBasicAuth(clientID, p.secret)
	oauthError(t, p.do(r), http.StatusBadRequest, "invalid_request")

	w = p.do(p.form("/oauth2/introspect", url.Values{"token": {"x"}}, false))
	oauthError(t, w, http.StatusUnauthorized, "invalid_client")

	if !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "Basic ") {
		t.Errorf("introspection WWW-Authenticate = %q", w.Header().Get("WWW-Authenticate"))
	}
}

func TestUserInfoTakesTheTokenFromTheBearerHeaderOnly(t *testing.T) {
	p := newProvider(t)

	for name, r := range map[string]*http.Request{
		"no token":           httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil),
		"a token in the URL": httptest.NewRequest(http.MethodGet, "/oauth2/userinfo?access_token=abc", nil),
	} {
		t.Run(name, func(t *testing.T) {
			w := p.do(r)
			oauthError(t, w, http.StatusUnauthorized, "invalid_token")

			if w.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Errorf("WWW-Authenticate = %q", w.Header().Get("WWW-Authenticate"))
			}
		})
	}

	r := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	r.Header.Set("Authorization", "Bearer not-a-token")
	w := p.do(r)
	oauthError(t, w, http.StatusUnauthorized, "invalid_token")

	if w.Header().Get("WWW-Authenticate") != `Bearer error="invalid_token"` {
		t.Errorf("WWW-Authenticate of a bad token = %q", w.Header().Get("WWW-Authenticate"))
	}
}

func TestCompletingASignInNeedsJSONAndABearerProof(t *testing.T) {
	p := newProvider(t)

	r := httptest.NewRequest(http.MethodPost, "/oauth2/login/complete", strings.NewReader("request=x"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	oauthError(t, p.do(r), http.StatusBadRequest, "invalid_request")

	r = httptest.NewRequest(http.MethodPost, "/oauth2/login/complete", strings.NewReader(`{"request":"x"}`))
	r.Header.Set("Content-Type", "application/json")
	w := p.do(r)
	oauthError(t, w, http.StatusUnauthorized, "access_denied")

	if w.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Errorf("WWW-Authenticate = %q", w.Header().Get("WWW-Authenticate"))
	}
}
