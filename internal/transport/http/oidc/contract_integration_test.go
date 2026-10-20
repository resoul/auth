//go:build integration

package oidc_test

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"go.airlance.org/auth/internal/testutil"
)

// The cases of the HTTP contract that need a registered client, on PostgreSQL: the in-memory store holds no data of
// the provider.

func newProviderWithClient(t *testing.T) *provider {
	t.Helper()

	return newProviderOn(t, testutil.PostgresStore(t), true)
}

func TestTheTokenEndpointRefusesWhatAClientMayNotDo(t *testing.T) {
	p := newProviderWithClient(t)
	grant := url.Values{"grant_type": {"authorization_code"}, "code": {"x"}, "redirect_uri": {redirectURI}, "code_verifier": {"v"}}

	t.Run("a wrong secret", func(t *testing.T) {
		r := p.form("/oauth2/token", grant, false)
		r.SetBasicAuth(clientID, "not-the-secret")
		oauthError(t, p.do(r), http.StatusUnauthorized, "invalid_client")
	})
	t.Run("an unknown grant type", func(t *testing.T) {
		oauthError(t, p.do(p.form("/oauth2/token", url.Values{"grant_type": {"password"}}, true)), http.StatusBadRequest, "unsupported_grant_type")
	})
	t.Run("a code that was never issued", func(t *testing.T) {
		oauthError(t, p.do(p.form("/oauth2/token", grant, true)), http.StatusBadRequest, "invalid_grant")
	})

	t.Run("an application asking to introspect", func(t *testing.T) {
		w := p.do(p.form("/oauth2/introspect", url.Values{"token": {"x"}}, true))
		oauthError(t, w, http.StatusUnauthorized, "invalid_client")
	})
}

// authorizeQuery is a valid authorization request of the registered client.
func authorizeQuery() url.Values {
	sum := sha256.Sum256([]byte("a verifier that is long enough to be a real PKCE verifier, 43+"))

	return url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI}, "scope": {"openid email"},
		"state": {"st-1"}, "nonce": {"n-1"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
}

func TestAnAuthorizationRequestThatCannotBeTrustedStaysOnTheProvider(t *testing.T) {
	p := newProviderWithClient(t)

	for name, change := range map[string]func(url.Values){
		"an unknown client":        func(q url.Values) { q.Set("client_id", "nobody") },
		"a foreign return address": func(q url.Values) { q.Set("redirect_uri", "https://evil.example.test/callback") },
		"no client":                func(q url.Values) { q.Del("client_id") },
	} {
		t.Run(name, func(t *testing.T) {
			q := authorizeQuery()
			change(q)

			w := p.do(httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil))
			if w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" {
				t.Fatalf("authorize = %d to %q, want a 400 page and no redirect", w.Code, w.Header().Get("Location"))
			}

			h := w.Header()
			if !strings.HasPrefix(h.Get("Content-Type"), "text/html") || h.Get("X-Frame-Options") != "DENY" ||
				!strings.Contains(h.Get("Content-Security-Policy"), "frame-ancestors 'none'") || h.Get("Cache-Control") != "no-store" {
				t.Errorf("error page headers = %v", h)
			}
		})
	}
}

func TestAnAuthorizationErrorGoesBackToTheClientWithTheIssuer(t *testing.T) {
	p := newProviderWithClient(t)

	for name, tc := range map[string]struct {
		change func(url.Values)
		method string
		status int
	}{
		"no PKCE":          {func(q url.Values) { q.Del("code_challenge") }, http.MethodGet, http.StatusFound},
		"a repeated state": {func(q url.Values) { q["state"] = []string{"a", "b"} }, http.MethodGet, http.StatusFound},
		"a repeated return address, the second foreign": {func(q url.Values) { q["redirect_uri"] = []string{redirectURI, "https://evil.example.test/cb"} }, http.MethodGet, http.StatusFound},
		"a scope without openid":                        {func(q url.Values) { q.Set("scope", "email") }, http.MethodGet, http.StatusFound},
		"a POST that has a query":                       {func(url.Values) {}, http.MethodPost, http.StatusSeeOther},
	} {
		t.Run(name, func(t *testing.T) {
			q := authorizeQuery()
			tc.change(q)

			var r *http.Request
			if tc.method == http.MethodPost {
				r = httptest.NewRequest(http.MethodPost, "/oauth2/authorize?client_id="+clientID, strings.NewReader(q.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			} else {
				r = httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil)
			}

			w := p.do(r)

			to, err := url.Parse(w.Header().Get("Location"))
			if w.Code != tc.status || err != nil || !strings.HasPrefix(to.String(), redirectURI+"?") {
				t.Fatalf("authorize = %d to %q, want %d back to the client", w.Code, w.Header().Get("Location"), tc.status)
			}

			back := to.Query()
			if back.Get("error") == "" || back.Get("iss") != issuer || back.Get("code") != "" {
				t.Errorf("error redirect = %v, want an error and the issuer, no code", back)
			}

			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
				t.Errorf("redirect headers = %v", w.Header())
			}
		})
	}
}

func TestAValidAuthorizationRequestBindsTheBrowserAndShowsTheSignIn(t *testing.T) {
	p := newProviderWithClient(t)

	w := p.do(httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+authorizeQuery().Encode(), nil))

	to, err := url.Parse(w.Header().Get("Location"))
	if w.Code != http.StatusSeeOther || err != nil || to.Path != "/oauth2/login" || to.Query().Get("request") == "" {
		t.Fatalf("authorize = %d to %q, want the sign-in page with the request", w.Code, w.Header().Get("Location"))
	}

	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %v, want the request binding only", cookies)
	}

	c := cookies[0]
	if c.Name != "__Host-airlance_oidc_req" || !c.Secure || !c.HttpOnly || c.Path != "/" || c.Domain != "" ||
		c.SameSite != http.SameSiteLaxMode || c.MaxAge <= 0 || c.Value == "" {
		t.Errorf("binding cookie = %+v", c)
	}

	// The page itself writes nothing of the request into its markup and keeps every protection header.
	page := p.do(httptest.NewRequest(http.MethodGet, "/oauth2/login?request=<script>", nil))
	if page.Code != http.StatusOK || strings.Contains(page.Body.String(), "<script>alert") || strings.Contains(page.Body.String(), "request=<script>") {
		t.Errorf("sign-in page = %d", page.Code)
	}

	if !strings.Contains(page.Header().Get("Content-Security-Policy"), "script-src 'self'") || page.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("sign-in page headers = %v", page.Header())
	}

	asset := p.do(httptest.NewRequest(http.MethodGet, "/oauth2/login/app.js", nil))
	if asset.Header().Get("Content-Type") != "text/javascript; charset=utf-8" || asset.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("script headers = %v", asset.Header())
	}
}
