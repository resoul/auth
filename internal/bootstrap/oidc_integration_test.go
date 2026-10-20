//go:build integration

package bootstrap_test

import (
	"bytes"
	"context"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"

	"go.airlance.org/auth/internal/adapter/crypto"
	"go.airlance.org/auth/internal/bootstrap"
	"go.airlance.org/auth/internal/config"
	doidc "go.airlance.org/auth/internal/domain/oidc"
	"go.airlance.org/auth/internal/testutil"
)

const (
	oidcIssuer   = testRPOrigin
	panelsReturn = "https://panels.example.test/auth/callback"
	videoReturn  = "https://video.example.test/auth/callback"
)

// oidcService is the real service with the OpenID Provider on.
type oidcService struct {
	*service
	cfg  config.Config
	base string
	smtp *testutil.FakeSMTP
	stop func()
	// lastAccess is the /v1 access token of the sign-in the last signIn made, which a test may use for the person's own API.
	lastAccess string
}

func newOIDCService(t *testing.T) *oidcService {
	t.Helper()
	s := newService(t)
	smtp := testutil.NewFakeSMTP(t)
	cfg, base := s.apiConfig(addrOf(smtp))
	// The tests' own receivers are on the loopback, which notices do not reach unless it is allowed.
	cfg.OIDC = config.OIDCConfig{Issuer: oidcIssuer, BackchannelAllow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	cfg.Keyring.OIDCSigning = &config.KeySet{ActiveKID: "oidc-a", Keys: map[string]config.KeyRef{
		"oidc-a": {KeyFile: testutil.WriteFile(t, "oidc-a.pem", testutil.NewRSAKeyPEM(t).Private)},
	}}
	stop := s.start(cfg)
	t.Cleanup(stop)
	waitReady(t, base)

	return &oidcService{service: s, cfg: cfg, base: base, smtp: smtp, stop: stop}
}

var secretLine = regexp.MustCompile(`client_secret: (\S+)`)

// register runs the operator's command and returns the secret it printed.
func (o *oidcService) register(t *testing.T, id string, redirect string) string {
	t.Helper()
	return o.registerWith(t, bootstrap.OIDCClientRequest{ID: id, Name: id, RedirectURIs: []string{redirect}})
}

func (o *oidcService) registerWith(t *testing.T, req bootstrap.OIDCClientRequest) string {
	t.Helper()

	var out bytes.Buffer

	req.Action = bootstrap.OIDCClientCreate

	err := bootstrap.OIDCClient(context.Background(), o.cfg, req, &out)
	if err != nil {
		t.Fatalf("register %s: %v", req.ID, err)
	}

	m := secretLine.FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("the command printed no secret: %s", out.String())
	}

	return m[1]
}

// browser is a browser of the provider's origin with a hand-made cookie jar. It follows nothing by itself: every
// redirect is returned, as a test needs to see where it goes.
type browser struct {
	t       *testing.T
	base    string
	cookies map[string]*http.Cookie
}

func newBrowser(t *testing.T, base string) *browser {
	return &browser{t: t, base: base, cookies: map[string]*http.Cookie{}}
}

var noFollow = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func (b *browser) do(req *http.Request) (*http.Response, string) {
	b.t.Helper()

	for _, ck := range b.cookies {
		req.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
	}

	resp, err := noFollow.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}

	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		b.t.Fatal(err)
	}

	for _, ck := range resp.Cookies() {
		if ck.MaxAge < 0 {
			delete(b.cookies, ck.Name)
		} else {
			b.cookies[ck.Name] = ck
		}
	}

	return resp, string(data)
}

// navigate is a top-level navigation from another site: a GET with the headers a browser sends then.
func (b *browser) navigate(rawURL string) (*http.Response, string) {
	b.t.Helper()

	req, err := http.NewRequest(http.MethodGet, b.base+rawURL, nil)
	if err != nil {
		b.t.Fatal(err)
	}

	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Fetch-Mode", "navigate")

	return b.do(req)
}

// page returns a page of the provider's own origin that shares this browser's cookies.
func (b *browser) page() *page { return &page{t: b.t, base: b.base, cookies: b.cookies} }

// app is a client application: its own state, nonce and verifier for one sign-in.
type app struct {
	id, secret, redirect   string
	state, nonce, verifier string
	// extra are parameters every authorization request of the application carries, such as scope and resource.
	extra url.Values
}

func newApp(t *testing.T, id, secret, redirect string) *app {
	t.Helper()

	random := func() string {
		s, _, err := crypto.OIDC{}.NewOIDCSecret() // 43 characters of the unreserved set
		if err != nil {
			t.Fatal(err)
		}

		return s
	}

	return &app{id: id, secret: secret, redirect: redirect, state: random(), nonce: random(), verifier: random()}
}

func (a *app) authorizeURL(extra url.Values) string {
	q := url.Values{
		"response_type": {"code"}, "client_id": {a.id}, "redirect_uri": {a.redirect}, "scope": {"openid email"},
		"state": {a.state}, "nonce": {a.nonce}, "code_challenge": {doidc.Challenge(a.verifier)}, "code_challenge_method": {"S256"},
	}
	for k, v := range a.extra {
		q[k] = v
	}

	for k, v := range extra {
		q[k] = v
	}

	return "/oauth2/authorize?" + q.Encode()
}

// token is the backchannel call of the application's backend.
func (a *app) token(t *testing.T, base string, form url.Values, basic bool) (*http.Response, map[string]any) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, base+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if basic {
		req.SetBasicAuth(url.QueryEscape(a.id), url.QueryEscape(a.secret))
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = resp.Body.Close() }()

	data, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(data, &out)

	return resp, out
}

func (a *app) exchange(t *testing.T, base, code string) (*http.Response, map[string]any) {
	return a.token(t, base, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {a.redirect}, "code_verifier": {a.verifier},
	}, true)
}

// codeFrom reads the code of a redirect back to the application.
func (a *app) codeFrom(t *testing.T, resp *http.Response) string {
	t.Helper()

	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, a.redirect+"?") {
		t.Fatalf("redirect to %q, want the application's return address (status %d)", loc, resp.StatusCode)
	}

	u, _ := url.Parse(loc)

	q := u.Query()
	if q.Get("state") != a.state || q.Get("iss") != oidcIssuer || q.Get("code") == "" {
		t.Fatalf("redirect %q lacks the state, the issuer or the code", loc)
	}

	return q.Get("code")
}

// signIn is what the sign-in page does: an emailed code, a new passkey, and the completion that returns the code.
func (o *oidcService) signIn(t *testing.T, b *browser, a *app, email string) (code string) {
	t.Helper()
	location := o.signInTo(t, b, a.authorizeURL(nil), email)

	return a.codeFrom(t, &http.Response{StatusCode: 302, Header: http.Header{"Location": {location}}})
}

// signInTo sends the browser to an authorization address of the provider (a path and query), signs the person in, and
// returns the address the provider sends the browser back to.
func (o *oidcService) signInTo(t *testing.T, b *browser, authorize, email string) string {
	t.Helper()
	id := o.proveTo(t, b, authorize, email)

	return o.completeTo(t, b, id, o.lastAccess)
}

// proveTo signs the person in at the sign-in page of an authorization address, without handing the sign-in to the
// provider. It returns the sign-in request id; the proof is left in o.lastAccess.
func (o *oidcService) proveTo(t *testing.T, b *browser, authorize, email string) string {
	t.Helper()

	resp, _ := b.navigate(authorize)

	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, "/oauth2/login?request=") || b.cookies["__Host-airlance_oidc_req"] == nil {
		t.Fatalf("authorize = %d %q, cookies %v: want the sign-in page and the binding cookie", resp.StatusCode, loc, resp.Header["Set-Cookie"])
	}

	requestID, _ := url.Parse(loc)
	id := requestID.Query().Get("request")

	pg := b.page()
	mailed := len(o.smtp.Messages())

	resp, body := pg.post("/v1/auth/email/start", `{"email": "`+email+`"}`)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("start = %d %s", resp.StatusCode, body)
	}

	flowID := jsonField(t, body, "flow_id")
	waitUntil(t, "the mail", func() bool { return len(o.smtp.Messages()) > mailed })

	m := mailedCode.FindStringSubmatch(o.smtp.Messages()[len(o.smtp.Messages())-1].Data)
	if m == nil {
		t.Fatal("the mail carries no code")
	}

	resp, body = pg.post("/v1/auth/email/verify", `{"flow_id": "`+flowID+`", "code": "`+m[1]+m[2]+`"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify = %d %s", resp.StatusCode, body)
	}

	resp, body = pg.registerPasskey(t, newAuthenticator(t), jsonField(t, body, "ticket"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register = %d %s", resp.StatusCode, body)
	}

	o.lastAccess = jsonField(t, body, "access_token")

	return id
}

func (o *oidcService) completeTo(t *testing.T, b *browser, requestID, accessToken string) string {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, b.base+"/oauth2/login/complete", strings.NewReader(`{"request_id": "`+requestID+`"}`))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, body := b.do(req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("complete = %d %s", resp.StatusCode, body)
	}

	return jsonField(t, body, "redirect_to")
}

// verifiedIDToken checks an ID token the way an application does: against the published key set, by the issuer's
// discovery document, with only the algorithm the document lists.
func verifiedIDToken(t *testing.T, base, idToken string) map[string]any {
	t.Helper()

	resp, err := http.Get(base + "/oauth2/jwks")
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = resp.Body.Close() }()

	data, _ := io.ReadAll(resp.Body)

	var set jose.JSONWebKeySet
	if err := json.Unmarshal(data, &set); err != nil || len(set.Keys) != 1 || set.Keys[0].Algorithm != "RS256" || !set.Keys[0].IsPublic() {
		t.Fatalf("jwks = %s, %v: want one public RS256 key", data, err)
	}

	parsed, err := josejwt.ParseSigned(idToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}

	var claims map[string]any
	if err := parsed.Claims(set.Keys[0], &claims); err != nil {
		t.Fatalf("the id token does not verify against the published key: %v", err)
	}

	return claims
}

func TestSingleSignOnAcrossTwoApplicationsOnTheRealService(t *testing.T) {
	o := newOIDCService(t)
	panelsSecret := o.register(t, "panels-web", panelsReturn)
	videoSecret := o.register(t, "video-web", videoReturn)
	panels, video := newApp(t, "panels-web", panelsSecret, panelsReturn), newApp(t, "video-web", videoSecret, videoReturn)
	browser := newBrowser(t, o.base)

	// The first application: the user signs in once, with a new passkey.
	code := o.signIn(t, browser, panels, "alice@example.test")

	resp, tokens := panels.exchange(t, o.base, code)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" || tokens["token_type"] != "Bearer" || tokens["refresh_token"] == nil {
		t.Fatalf("token = %d %v headers %v", resp.StatusCode, tokens, resp.Header)
	}

	claims := verifiedIDToken(t, o.base, tokens["id_token"].(string))
	if claims["iss"] != oidcIssuer || claims["aud"] != "panels-web" || claims["nonce"] != panels.nonce || claims["email"] != "alice@example.test" {
		t.Errorf("id token claims = %v", claims)
	}

	// The shared sign-in cookie: host-only, HttpOnly, Secure, Lax.
	sso := browser.cookies["__Host-airlance_sso"]
	if sso == nil || !sso.HttpOnly || !sso.Secure || sso.Path != "/" || sso.Domain != "" || sso.SameSite != http.SameSiteLaxMode || sso.MaxAge <= 0 {
		t.Fatalf("sso cookie = %+v", sso)
	}

	if browser.cookies["__Host-airlance_oidc_req"] != nil {
		t.Error("the binding cookie of a finished request was not cleared")
	}

	// UserInfo with the access token agrees with the ID token.
	req, _ := http.NewRequest(http.MethodGet, o.base+"/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokens["access_token"].(string))

	info, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	var infoBody map[string]any

	_ = json.NewDecoder(info.Body).Decode(&infoBody)

	_ = info.Body.Close()
	if info.StatusCode != http.StatusOK || infoBody["sub"] != claims["sub"] || infoBody["email"] != "alice@example.test" || info.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("userinfo = %d %v", info.StatusCode, infoBody)
	}

	// The second application: no email, no passkey. The browser holds the cookie, so the code comes straight back.
	resp, _ = browser.navigate(video.authorizeURL(nil))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize with the shared sign-in = %d %q, want a redirect with a code", resp.StatusCode, resp.Header.Get("Location"))
	}

	resp, vtokens := video.exchange(t, o.base, video.codeFrom(t, resp))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("second token = %d %v", resp.StatusCode, vtokens)
	}

	vclaims := verifiedIDToken(t, o.base, vtokens["id_token"].(string))
	if vclaims["sub"] != claims["sub"] || vclaims["sid"] != claims["sid"] || vclaims["aud"] != "video-web" || vclaims["nonce"] != video.nonce {
		t.Errorf("second application's claims = %v", vclaims)
	}

	if n := count(t, o.service, "oidc_op_sessions"); n != 1 {
		t.Errorf("%d OP sessions, want the one shared sign-in", n)
	}

	if n := count(t, o.service, "oidc_grants"); n != 2 {
		t.Errorf("%d grants, want one per application", n)
	}

	// Nothing the provider stores is a usable secret.
	for _, table := range []string{"oidc_authorization_codes", "oidc_refresh_tokens", "oidc_op_sessions", "oidc_client_secrets"} {
		for _, secret := range []string{code, tokens["refresh_token"].(string), sso.Value, panelsSecret} {
			if o.contains(t, table, secret) {
				t.Errorf("%s stores a secret in the clear", table)
			}
		}
	}
}

func (o *oidcService) contains(t *testing.T, table, secret string) bool {
	t.Helper()

	var n int

	row := o.db.QueryRow(`SELECT count(*) FROM `+table+` t WHERE t::text LIKE '%' || $1 || '%'`, secret)
	if err := row.Scan(&n); err != nil {
		t.Fatal(err)
	}

	return n > 0
}

func TestTheProviderPublishesWhatItImplements(t *testing.T) {
	o := newOIDCService(t)

	resp, err := http.Get(o.base + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}

	var doc map[string]any

	_ = json.NewDecoder(resp.Body).Decode(&doc)

	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || doc["issuer"] != oidcIssuer {
		t.Fatalf("discovery = %d %v", resp.StatusCode, doc)
	}

	for _, key := range []string{"authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri", "revocation_endpoint", "introspection_endpoint", "end_session_endpoint"} {
		u, _ := url.Parse(doc[key].(string))
		if !strings.HasPrefix(doc[key].(string), oidcIssuer+"/oauth2/") {
			t.Errorf("%s = %v", key, doc[key])
		}
		// The document is served from a test address, not the issuer's; the path must exist and not be a 404.
		resp, err := noFollow.Get(o.base + u.Path)
		if err != nil {
			t.Fatal(err)
		}

		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			t.Errorf("%s (%s) is advertised but not served", key, u.Path)
		}
	}

	for key, want := range map[string]any{
		"response_types_supported": "code", "code_challenge_methods_supported": "S256", "id_token_signing_alg_values_supported": "RS256",
		"token_endpoint_auth_methods_supported": "client_secret_basic", "revocation_endpoint_auth_methods_supported": "client_secret_basic",
		"introspection_endpoint_auth_methods_supported": "client_secret_basic",
	} {
		list, _ := doc[key].([]any)
		if len(list) != 1 || list[0] != want {
			t.Errorf("%s = %v, want exactly [%v]", key, doc[key], want)
		}
	}

	if doc["authorization_response_iss_parameter_supported"] != true {
		t.Error("discovery does not announce the iss response parameter")
	}

	for _, announced := range []string{"backchannel_logout_supported", "backchannel_logout_session_supported"} {
		if doc[announced] != true {
			t.Errorf("discovery does not announce %s", announced)
		}
	}

	for _, absent := range []string{"registration_endpoint", "device_authorization_endpoint", "pushed_authorization_request_endpoint"} {
		if doc[absent] != nil {
			t.Errorf("discovery announces %s, which is not implemented", absent)
		}
	}
}

func TestAuthorizeAndTokenEndpointsOnTheWire(t *testing.T) {
	o := newOIDCService(t)
	secret := o.register(t, "panels-web", panelsReturn)
	a := newApp(t, "panels-web", secret, panelsReturn)
	b := newBrowser(t, o.base)

	t.Run("an untrusted client or return address is an error page and no redirect", func(t *testing.T) {
		for name, u := range map[string]string{
			"unknown client": newApp(t, "nobody", "x", panelsReturn).authorizeURL(nil),
			"foreign return": (&app{id: "panels-web", redirect: "https://evil.example.test/cb", state: a.state, nonce: a.nonce, verifier: a.verifier}).authorizeURL(nil),
		} {
			resp, body := b.navigate(u)
			if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" || !strings.Contains(body, "Sign-in problem") {
				t.Errorf("%s: %d %q", name, resp.StatusCode, resp.Header.Get("Location"))
			}

			csp := resp.Header.Get("Content-Security-Policy")
			if !strings.Contains(csp, "frame-ancestors 'none'") || !strings.Contains(csp, "default-src 'none'") || resp.Header.Get("Cache-Control") != "no-store" {
				t.Errorf("%s: the error page is missing its security headers: %v", name, resp.Header)
			}
		}
	})

	t.Run("a bad request goes back to the application with the state and the issuer", func(t *testing.T) {
		resp, _ := b.navigate(a.authorizeURL(url.Values{"code_challenge_method": {"plain"}}))

		loc, _ := url.Parse(resp.Header.Get("Location"))
		if resp.StatusCode != http.StatusFound || loc == nil || loc.Query().Get("error") != "invalid_request" || loc.Query().Get("state") != a.state || loc.Query().Get("iss") != oidcIssuer {
			t.Errorf("plain PKCE: %d %q", resp.StatusCode, resp.Header.Get("Location"))
		}
	})

	t.Run("a repeated parameter is refused, in the query and in a form", func(t *testing.T) {
		resp, _ := b.navigate(a.authorizeURL(nil) + "&state=other")
		if loc := resp.Header.Get("Location"); !strings.Contains(loc, "error=invalid_request") {
			t.Errorf("repeated state in a GET: %q", loc)
		}

		form := a.authorizeURL(nil)[len("/oauth2/authorize?"):]
		req, _ := http.NewRequest(http.MethodPost, o.base+"/oauth2/authorize?x=1", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "cross-site")

		resp, _ = b.do(req)
		if loc := resp.Header.Get("Location"); !strings.Contains(loc, "error=invalid_request") {
			t.Errorf("a POST that also has a query: %q", loc)
		}
	})

	t.Run("a form post from the application's page is accepted", func(t *testing.T) {
		form := a.authorizeURL(nil)[len("/oauth2/authorize?"):]
		req, _ := http.NewRequest(http.MethodPost, o.base+"/oauth2/authorize", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "https://panels.example.test")
		req.Header.Set("Sec-Fetch-Site", "cross-site")

		resp, _ := newBrowser(t, o.base).do(req)
		if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/oauth2/login?request=") {
			t.Errorf("POST authorize = %d %q", resp.StatusCode, resp.Header.Get("Location"))
		}
	})

	t.Run("completing a sign-in cannot be done from another site", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, o.base+"/oauth2/login/complete", strings.NewReader(`{"request_id": "x"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "https://evil.example")
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		req.Header.Set("Authorization", "Bearer a.b.c")

		resp, _ := b.do(req)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("a cross-site completion = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("the token endpoint", func(t *testing.T) {
		form := url.Values{"grant_type": {"authorization_code"}, "code": {"x"}, "redirect_uri": {panelsReturn}, "code_verifier": {a.verifier}}

		resp, body := a.token(t, o.base, form, false)
		if resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Basic") || body["error"] != "invalid_client" {
			t.Errorf("no credentials = %d %v %v", resp.StatusCode, body, resp.Header)
		}

		resp, body = a.token(t, o.base, form, true)
		if resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" || resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("a made-up code = %d %v", resp.StatusCode, body)
		}

		resp, body = a.token(t, o.base, url.Values{"grant_type": {"password"}}, true)
		if resp.StatusCode != http.StatusBadRequest || body["error"] != "unsupported_grant_type" {
			t.Errorf("password grant = %d %v", resp.StatusCode, body)
		}
		// The secret in the body is not a credential.
		withBody := url.Values{"grant_type": {"authorization_code"}, "client_id": {"panels-web"}, "client_secret": {secret}, "code": {"x"}}
		if resp, _ := a.token(t, o.base, withBody, false); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("client_secret_post = %d, want 401", resp.StatusCode)
		}
		// A JSON body is refused.
		req, _ := http.NewRequest(http.MethodPost, o.base+"/oauth2/token", strings.NewReader(`{"grant_type": "authorization_code"}`))
		req.SetBasicAuth("panels-web", secret)
		req.Header.Set("Content-Type", "application/json")

		jr, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}

		_ = jr.Body.Close()
		if jr.StatusCode != http.StatusBadRequest {
			t.Errorf("a JSON body = %d, want 400", jr.StatusCode)
		}
		// GET is not a token request.
		gr, err := http.Get(o.base + "/oauth2/token?grant_type=authorization_code")
		if err != nil {
			t.Fatal(err)
		}

		_ = gr.Body.Close()
		if gr.StatusCode != http.StatusMethodNotAllowed && gr.StatusCode != http.StatusNotFound {
			t.Errorf("GET /oauth2/token = %d", gr.StatusCode)
		}
	})

	t.Run("userinfo accepts a Bearer header only", func(t *testing.T) {
		for name, req := range map[string]func() *http.Request{
			"no token": func() *http.Request {
				r, _ := http.NewRequest(http.MethodGet, o.base+"/oauth2/userinfo", nil)
				return r
			},
			"a token in query": func() *http.Request {
				r, _ := http.NewRequest(http.MethodGet, o.base+"/oauth2/userinfo?access_token=a.b.c", nil)
				return r
			},
			"a bad token": func() *http.Request {
				r, _ := http.NewRequest(http.MethodGet, o.base+"/oauth2/userinfo", nil)
				r.Header.Set("Authorization", "Bearer a.b.c")

				return r
			},
		} {
			resp, err := http.DefaultClient.Do(req())
			if err != nil {
				t.Fatal(err)
			}

			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Bearer") {
				t.Errorf("%s: %d %v", name, resp.StatusCode, resp.Header)
			}
		}
	})

	t.Run("the sign-in page and its script", func(t *testing.T) {
		resp, body := b.navigate("/oauth2/login?request=x")
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, `src="/oauth2/login/app.js"`) || strings.Contains(body, "<script>") {
			t.Errorf("login page = %d, inline script or no script link", resp.StatusCode)
		}

		if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") {
			t.Errorf("login page CSP = %q", csp)
		}

		if strings.Contains(body, "request=x") {
			t.Error("the request id from the address is written into the page")
		}

		resp, js := b.navigate("/oauth2/login/app.js")
		if resp.StatusCode != http.StatusOK || !strings.Contains(js, "/oauth2/login/complete") || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("app.js = %d", resp.StatusCode)
		}
	})
}

func TestLogoutOnTheRealService(t *testing.T) {
	o := newOIDCService(t)
	notices := make(chan string, 4)
	client := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		notices <- r.PostForm.Get("logout_token")
	}))
	t.Cleanup(client.Close)

	const after = "https://panels.example.test/signed-out?source=auth"

	secret := o.registerWith(t, bootstrap.OIDCClientRequest{
		ID: "panels-web", Name: "Panels", RedirectURIs: []string{panelsReturn}, PostLogoutURIs: []string{after}, BackchannelURI: client.URL,
	})
	app := newApp(t, "panels-web", secret, panelsReturn)
	b := newBrowser(t, o.base)
	_, tokens := app.exchange(t, o.base, o.signIn(t, b, app, "alice@example.test"))
	hint := tokens["id_token"].(string)
	query := url.Values{"id_token_hint": {hint}, "post_logout_redirect_uri": {after}, "state": {"back<&\"x"}}.Encode()

	// A link, or an image on another site, cannot sign anyone out: a GET only asks.
	resp, body := b.navigate("/oauth2/logout?" + query)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `name="confirm"`) || strings.Contains(body, `"back<&"`) || b.cookies["__Host-airlance_sso"] == nil {
		t.Fatalf("logout GET = %d, want a page that asks (and the cookie kept): %s", resp.StatusCode, body)
	}

	if !strings.Contains(body, "back&lt;&amp;&#34;x") {
		t.Errorf("the state is not escaped in the page: %s", body)
	}

	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("the confirmation page can be framed: %q", csp)
	}

	if n := countWhere(t, o.service, "oidc_op_sessions", "revoked_at IS NOT NULL"); n != 0 {
		t.Fatal("a GET ended the sign-in")
	}

	token := regexp.MustCompile(`name="confirm" value="([0-9a-f]+)"`).FindStringSubmatch(body)
	if token == nil {
		t.Fatalf("the confirmation page carries no token: %s", body)
	}
	// A form posted from another site is refused before anything happens.
	form := url.Values{"confirm": {"1"}, "id_token_hint": {hint}}

	post := func(site string) (*http.Response, string) {
		req, _ := http.NewRequest(http.MethodPost, o.base+"/oauth2/logout", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", site)

		if site == "cross-site" {
			req.Header.Set("Origin", "https://evil.example")
		}

		return b.do(req)
	}
	if resp, _ := post("cross-site"); resp.StatusCode != http.StatusForbidden || countWhere(t, o.service, "oidc_op_sessions", "revoked_at IS NOT NULL") != 0 {
		t.Fatalf("a cross-site logout post = %d: it must be refused", resp.StatusCode)
	}

	// A same-origin post that did not come from the page (a trusted frontend, say) has no token and ends nothing.
	if resp, _ := post("same-origin"); resp.StatusCode != http.StatusBadRequest || countWhere(t, o.service, "oidc_op_sessions", "revoked_at IS NOT NULL") != 0 {
		t.Fatalf("a logout post without the token = %d: it must be refused", resp.StatusCode)
	}

	// The person confirms on the provider's own page.
	form.Set("confirm", token[1])
	form.Set("post_logout_redirect_uri", "https://evil.example/signed-out")

	if resp, body := post("same-origin"); resp.StatusCode != http.StatusBadRequest || strings.Contains(body, `<a `) || countWhere(t, o.service, "oidc_op_sessions", "revoked_at IS NOT NULL") != 0 {
		t.Fatalf("an unregistered return address must neither end the sign-in nor appear as a link: %d %s", resp.StatusCode, body)
	}

	form.Set("post_logout_redirect_uri", after)
	form.Set("state", "back<&\"x")

	resp, body = post("same-origin")
	wantReturn := after + "&" + url.Values{"state": {form.Get("state")}}.Encode()
	// A cross-origin HTTP redirect of this form POST is blocked by form-action 'self' in real browsers.
	// Commit a signed-out document first; its ordinary link can return to the validated client with state intact.
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Location") != "" || !strings.Contains(body, "<h1>Signed out</h1>") || !strings.Contains(body, `href="`+html.EscapeString(wantReturn)+`"`) {
		t.Fatalf("confirmed logout must show a signed-out page with the escaped return link: %d %s", resp.StatusCode, body)
	}

	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self';") || !strings.Contains(csp, "script-src 'self';") || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("the signed-out page must keep the strict CSP and avoid caching: %q", csp)
	}

	if b.cookies["__Host-airlance_sso"] != nil {
		t.Error("the sign-in cookie was not cleared")
	}
	// The tokens of the application are dead, and the sign-in page's device session with them.
	req, _ := http.NewRequest(http.MethodGet, o.base+"/oauth2/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokens["access_token"].(string))

	if info, err := http.DefaultClient.Do(req); err != nil || info.StatusCode != http.StatusUnauthorized {
		t.Errorf("userinfo after logout = %v, %v", info, err)
	}

	if resp, _ := app.token(t, o.base, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}}, true); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("refresh after logout = %d", resp.StatusCode)
	}

	if n := countWhere(t, o.service, "sessions", "revoked_at IS NULL"); n != 0 {
		t.Errorf("%d device sessions are live after the logout", n)
	}

	// The real worker tells the client's backend, within a few seconds.
	var notice string
	select {
	case notice = <-notices:
	case <-time.After(15 * time.Second):
		t.Fatal("the client was not told that the sign-in ended")
	}

	claims := verifiedLogoutToken(t, o.base, notice)
	if claims["aud"] != "panels-web" || claims["iss"] != oidcIssuer || claims["sid"] == nil || claims["nonce"] != nil {
		t.Errorf("logout token = %v", claims)
	}

	if idClaims := verifiedIDToken(t, o.base, hint); idClaims["sid"] != claims["sid"] || idClaims["sub"] != claims["sub"] {
		t.Errorf("the notice names sid %v and sub %v; the ID token had %v and %v", claims["sid"], claims["sub"], idClaims["sid"], idClaims["sub"])
	}

	// With no return address and no remaining sign-in, the page has no continuation link.
	_, body = b.navigate("/oauth2/logout")

	token = regexp.MustCompile(`name="confirm" value="([0-9a-f]+)"`).FindStringSubmatch(body)
	if token == nil {
		t.Fatal("the anonymous confirmation page carries no token")
	}

	form = url.Values{"confirm": {token[1]}}

	resp, body = post("same-origin")
	if resp.StatusCode != http.StatusOK || strings.Contains(body, `<a `) || !strings.Contains(body, "You are not signed in here.") {
		t.Fatalf("logout without a return address = %d %s", resp.StatusCode, body)
	}
}

func TestRevocationOnTheRealService(t *testing.T) {
	o := newOIDCService(t)
	secret := o.register(t, "panels-web", panelsReturn)
	app := newApp(t, "panels-web", secret, panelsReturn)
	b := newBrowser(t, o.base)
	_, tokens := app.exchange(t, o.base, o.signIn(t, b, app, "alice@example.test"))

	revoke := func(basic bool, token string) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, o.base+"/oauth2/revoke", strings.NewReader(url.Values{"token": {token}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		if basic {
			req.SetBasicAuth(app.id, app.secret)
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}

		_ = resp.Body.Close()

		return resp
	}
	if resp := revoke(false, tokens["refresh_token"].(string)); resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Basic") {
		t.Errorf("revoke without credentials = %d %v", resp.StatusCode, resp.Header)
	}

	if resp := revoke(true, "junk"); resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("revoke of junk = %d, want 200", resp.StatusCode)
	}

	if resp := revoke(true, tokens["refresh_token"].(string)); resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke = %d", resp.StatusCode)
	}

	if resp, _ := app.token(t, o.base, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens["refresh_token"].(string)}}, true); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a revoked refresh token still works: %d", resp.StatusCode)
	}
	// GET is not a revocation.
	if resp, err := http.Get(o.base + "/oauth2/revoke?token=x"); err != nil || (resp.StatusCode != http.StatusMethodNotAllowed && resp.StatusCode != http.StatusNotFound) {
		t.Errorf("GET /oauth2/revoke = %v, %v", resp, err)
	}
}

// verifiedLogoutToken checks a logout token the way a client's backend does: the key set, the type and the algorithm.
func verifiedLogoutToken(t *testing.T, base, token string) map[string]any {
	t.Helper()

	resp, err := http.Get(base + "/oauth2/jwks")
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = resp.Body.Close() }()

	data, _ := io.ReadAll(resp.Body)

	var set jose.JSONWebKeySet
	if err := json.Unmarshal(data, &set); err != nil || len(set.Keys) != 1 {
		t.Fatalf("jwks = %s, %v", data, err)
	}

	parsed, err := josejwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}

	if typ := parsed.Headers[0].ExtraHeaders[jose.HeaderType]; typ != "logout+jwt" {
		t.Errorf("typ = %v", typ)
	}

	var claims map[string]any
	if err := parsed.Claims(set.Keys[0], &claims); err != nil {
		t.Fatalf("the logout token does not verify against the published key: %v", err)
	}

	return claims
}
