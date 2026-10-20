//go:build integration

package bootstrap_test

import (
	"bytes"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"go.airlance.org/auth/examples/bff"
	"go.airlance.org/auth/examples/resourcecheck"
	"go.airlance.org/auth/internal/bootstrap"
)

// reroute sends what is meant for the issuer's address to the service under test, as DNS would.
type reroute struct{ to *url.URL }

func (r reroute) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == "example.test" {
		c := req.Clone(req.Context())
		c.URL.Scheme, c.URL.Host = r.to.Scheme, r.to.Host

		return http.DefaultTransport.RoundTrip(c)
	}

	return http.DefaultTransport.RoundTrip(req)
}

// bffApp is an application built on examples/bff, served on a loopback address.
type bffApp struct {
	srv    *httptest.Server
	client *http.Client
	logs   *bytes.Buffer
}

func (o *oidcService) startBFF(t *testing.T, id string, upstream *url.URL) *bffApp {
	t.Helper()

	logs := &bytes.Buffer{}
	app := &bffApp{logs: logs}

	var handler http.Handler

	app.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(app.srv.Close)
	secret := o.registerWith(t, bootstrap.OIDCClientRequest{
		ID: id, Name: id, RedirectURIs: []string{app.srv.URL + "/auth/callback"},
		PostLogoutURIs: []string{app.srv.URL + "/logged-out"}, BackchannelURI: app.srv.URL + "/auth/backchannel-logout",
	})
	o.operate(t, bootstrap.OIDCResourceRequest{Action: bootstrap.OIDCResourceAllow, ID: "platform-api", ClientID: id, Scopes: []string{"messages:read", "messages:send"}})
	base, _ := url.Parse(o.base)

	vault, err := bff.NewVault("v1", map[string][]byte{"v1": bytes.Repeat([]byte{9}, 32)})
	if err != nil {
		t.Fatal(err)
	}

	a, err := bff.New(bff.Config{
		Issuer: oidcIssuer, ClientID: id, ClientSecret: secret, BaseURL: app.srv.URL, Scopes: []string{"email"},
		Resources: []bff.Resource{{Name: "platform", URI: platformResource, Scopes: []string{"messages:send"}, Upstream: upstream}},
		Store:     bff.NewMemoryStore(nil), Vault: vault, InsecureCookies: true,
		HTTPClient: &http.Client{Timeout: 10 * time.Second, Transport: reroute{to: base}},
	})
	if err != nil {
		t.Fatal(err)
	}

	handler = a.Handler()
	jar, _ := cookiejar.New(nil)
	app.client = &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	return app
}

func (a *bffApp) do(t *testing.T, method, path string, hdr map[string]string) (*http.Response, string) {
	t.Helper()

	req, _ := http.NewRequest(method, a.srv.URL+path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}

	resp, err := a.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = resp.Body.Close() }()

	data, _ := io.ReadAll(resp.Body)

	return resp, string(data)
}

// providerPath turns an absolute address of the issuer into the path and query the service answers.
func providerPath(t *testing.T, raw string) string {
	t.Helper()

	u, err := url.Parse(raw)
	if err != nil || u.Host != "example.test" {
		t.Fatalf("%q is not an address of the issuer", raw)
	}

	return u.RequestURI()
}

// signInBFF runs the sign-in of an application with a browser that already has (or does not have) the provider's cookie.
func (o *oidcService) signInBFF(t *testing.T, b *browser, app *bffApp, email string, newPerson bool) {
	t.Helper()

	resp, _ := app.do(t, http.MethodGet, "/login?return_to=/home", nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login = %d", resp.StatusCode)
	}

	authorize := providerPath(t, resp.Header.Get("Location"))

	var back string
	if newPerson {
		back = o.signInTo(t, b, authorize, email)
	} else {
		// The shared sign-in answers at once: the provider asks for nothing.
		r, _ := b.navigate(authorize)
		if r.StatusCode != http.StatusFound {
			t.Fatalf("authorize with the shared sign-in = %d %q", r.StatusCode, r.Header.Get("Location"))
		}

		back = r.Header.Get("Location")
	}

	u, _ := url.Parse(back)

	resp, _ = app.do(t, http.MethodGet, u.RequestURI(), nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/home" {
		t.Fatalf("callback = %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestBFFOnTheRealService(t *testing.T) {
	o := newOIDCService(t)
	o.operate(t, bootstrap.OIDCResourceRequest{Action: bootstrap.OIDCResourceRegister, ID: "platform-api", Name: "Platform", URI: platformResource,
		Audience: "platform-api", Scopes: []string{"messages:read", "messages:send"}})

	// An API of its own, checking tokens with the verifier a service would copy, from the published key set.
	check, err := resourcecheck.New(resourcecheck.Config{Issuer: oidcIssuer, Audience: "platform-api", JWKSURL: o.base + "/oauth2/jwks"})
	if err != nil {
		t.Fatal(err)
	}

	var sawSubjects []string

	api := httptest.NewServer(check.Require("messages:send")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := resourcecheck.FromContext(r.Context())
		sawSubjects = append(sawSubjects, c.Subject)

		if r.Header.Get("Cookie") != "" {
			t.Error("the application's cookie reached the API")
		}

		_, _ = w.Write([]byte("hello " + r.URL.Path))
	})))
	t.Cleanup(api.Close)
	upstream, _ := url.Parse(api.URL)

	first, second := o.startBFF(t, "bff-one", upstream), o.startBFF(t, "bff-two", upstream)
	b := newBrowser(t, o.base)

	// The first application: the person signs in once, with a new passkey.
	o.signInBFF(t, b, first, "alice@example.test", true)
	resp, body := first.do(t, http.MethodGet, "/api/me", nil)

	var me map[string]any

	_ = json.Unmarshal([]byte(body), &me)
	if resp.StatusCode != http.StatusOK || me["issuer"] != oidcIssuer || me["subject"] == "" || strings.Contains(body, "token") {
		t.Fatalf("me = %d %s", resp.StatusCode, body)
	}

	if resp, body := first.do(t, http.MethodGet, "/api/platform/messages", nil); resp.StatusCode != http.StatusOK || body != "hello /messages" {
		t.Fatalf("the API call = %d %q", resp.StatusCode, body)
	}
	// The browser holds one opaque cookie and no token.
	u, _ := url.Parse(first.srv.URL)
	for _, c := range first.client.Jar.Cookies(u) {
		if strings.Contains(c.Value, ".") || len(c.Value) > 64 {
			t.Errorf("cookie %s looks like a token", c.Name)
		}
	}

	// The second application: no passkey, no sign-in page. One sign-in, two applications.
	o.signInBFF(t, b, second, "", false)

	var meTwo map[string]any

	_, body = second.do(t, http.MethodGet, "/api/me", nil)

	_ = json.Unmarshal([]byte(body), &meTwo)
	if meTwo["subject"] != me["subject"] {
		t.Errorf("the two applications see %v and %v", me["subject"], meTwo["subject"])
	}

	if resp, _ := second.do(t, http.MethodGet, "/api/platform/x", nil); resp.StatusCode != http.StatusOK {
		t.Errorf("the second application's API call = %d", resp.StatusCode)
	}

	if len(sawSubjects) != 2 || sawSubjects[0] != sawSubjects[1] {
		t.Errorf("the API saw %v", sawSubjects)
	}

	// Signing out of the first ends the shared sign-in: the person confirms at the provider, and both applications are told.
	resp, _ = first.do(t, http.MethodPost, "/logout", map[string]string{"Sec-Fetch-Site": "cross-site"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a cross-site logout = %d", resp.StatusCode)
	}

	resp, _ = first.do(t, http.MethodPost, "/logout", map[string]string{"Sec-Fetch-Site": "same-origin"})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout = %d", resp.StatusCode)
	}

	end := providerPath(t, resp.Header.Get("Location"))
	if r, _ := first.do(t, http.MethodGet, "/api/me", nil); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("me after logout = %d", r.StatusCode)
	}

	_, page := b.navigate(end)

	token := regexp.MustCompile(`name="confirm" value="([0-9a-f]+)"`).FindStringSubmatch(page)
	if token == nil {
		t.Fatalf("no confirmation page: %s", page)
	}

	form := url.Values{"confirm": {token[1]}}

	for _, name := range []string{"client_id", "post_logout_redirect_uri", "state", "id_token_hint"} {
		if m := regexp.MustCompile(`name="` + name + `" value="([^"]*)"`).FindStringSubmatch(page); m != nil {
			form.Set(name, html.UnescapeString(m[1]))
		}
	}

	req, _ := http.NewRequest(http.MethodPost, o.base+"/oauth2/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	_, done := b.do(req)

	link := regexp.MustCompile(`<a href="([^"]+)">Return`).FindStringSubmatch(done)
	if link == nil {
		t.Fatalf("no way back: %s", done)
	}

	back, _ := url.Parse(html.UnescapeString(link[1]))
	if resp, body := first.do(t, http.MethodGet, back.RequestURI(), nil); resp.StatusCode != http.StatusOK || !strings.Contains(body, "signed out") {
		t.Errorf("the return after logout = %d %s", resp.StatusCode, body)
	}
	// The notice reaches the second application's backend, which closes its session.
	waitUntil(t, "the second application's session to end", func() bool {
		r, _ := second.do(t, http.MethodGet, "/api/me", nil)
		return r.StatusCode == http.StatusUnauthorized
	})

	if r, _ := second.do(t, http.MethodGet, "/api/platform/x", nil); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("an API call after the notice = %d", r.StatusCode)
	}

	for _, app := range []*bffApp{first, second} {
		if strings.Contains(app.logs.String(), "code=") {
			t.Error("a code reached a log")
		}
	}
}
