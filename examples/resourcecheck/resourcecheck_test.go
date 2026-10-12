package resourcecheck_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"airlance.org/auth/examples/resourcecheck"
	"airlance.org/auth/internal/adapter/jwt"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/testutil"
)

const issuer = "https://auth.example.test"

var t0 = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

// site is the issuer as an API sees it: a key set URL, and a discovery document.
type site struct {
	t       *testing.T
	srv     *httptest.Server
	mu      sync.Mutex
	jwks    []byte
	status  int
	hits    int
	jwksURI string
	issuer  string
}

func newSite(t *testing.T, jwks []byte) *site {
	s := &site{t: t, jwks: jwks, status: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/jwks", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.hits++
		if s.status != http.StatusOK {
			w.WriteHeader(s.status)
			return
		}
		_, _ = w.Write(s.jwks)
	})
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		_, _ = w.Write([]byte(`{"issuer":"` + s.issuer + `","jwks_uri":"` + s.jwksURI + `"}`))
	})
	s.srv = httptest.NewServer(mux)
	s.issuer, s.jwksURI = s.srv.URL, s.srv.URL+"/oauth2/jwks"
	t.Cleanup(s.srv.Close)
	return s
}

func (s *site) set(jwks []byte, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jwks, s.status = jwks, status
}

func (s *site) requests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits
}

type env struct {
	t      *testing.T
	clock  *testutil.FakeClock
	site   *site
	files  map[string]string
	ring   *jwt.RSARing
	signer *jwt.OIDCTokens
	user   identity.UserID
}

// keyFile writes a new RSA key of its own: testutil shares one, and these tests need keys that differ.
func keyFile(t *testing.T, name string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return testutil.WriteFile(t, name+".pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func ringOf(t *testing.T, active string, files map[string]string) *jwt.RSARing {
	t.Helper()
	ring, err := jwt.LoadRSARing(active, files)
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

// newRing is a ring of new keys, one for each kid.
func newRing(t *testing.T, active string, kids ...string) (*jwt.RSARing, map[string]string) {
	t.Helper()
	files := map[string]string{}
	for _, kid := range kids {
		files[kid] = keyFile(t, kid)
	}
	return ringOf(t, active, files), files
}

func signerOf(t *testing.T, ring *jwt.RSARing, clock *testutil.FakeClock) *jwt.OIDCTokens {
	t.Helper()
	s, err := jwt.NewOIDCTokens(ring, clock, issuer, 5*time.Minute, 5*time.Minute, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, clock: testutil.NewFakeClock(t0)}
	e.ring, e.files = newRing(t, "oidc-a", "oidc-a")
	jwks, err := e.ring.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	e.site = newSite(t, jwks)
	e.signer = signerOf(t, e.ring, e.clock)
	e.user = testutil.NewFactory(t, t0).User(testutil.UserSpec{}).ID()
	return e
}

func (e *env) verifier(audience string, mutate ...func(*resourcecheck.Config)) *resourcecheck.Verifier {
	e.t.Helper()
	cfg := resourcecheck.Config{Issuer: issuer, Audience: audience, JWKSURL: e.site.jwksURI, Now: e.clock.Now}
	for _, m := range mutate {
		m(&cfg)
	}
	v, err := resourcecheck.New(cfg)
	if err != nil {
		e.t.Fatal(err)
	}
	return v
}

// token is an access token of the provider for the audience.
func (e *env) token(audience string, scopes ...string) string {
	e.t.Helper()
	tok, _, err := e.signer.SignOIDCAccessToken(port.OIDCAccessClaims{
		Subject: e.user, ClientID: "panels-web", Audience: audience, Scope: scopes, SessionID: "sid-1", GrantID: "grant-1", AuthTime: t0,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return tok.Value
}

func refused(t *testing.T, v *resourcecheck.Verifier, token, why string) {
	t.Helper()
	if _, err := v.Verify(context.Background(), token); !errors.Is(err, resourcecheck.ErrInvalidToken) {
		t.Errorf("%s: err = %v, want ErrInvalidToken", why, err)
	}
}

func TestAnAPIAcceptsItsOwnTokenAndReadsItsScopes(t *testing.T) {
	e := newEnv(t)
	v := e.verifier("platform-api")
	claims, err := v.Verify(context.Background(), e.token("platform-api", "messages:read", "messages:send"))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != e.user.String() || claims.ClientID != "panels-web" || claims.GrantID != "grant-1" || claims.TokenID == "" || !claims.AuthTime.Equal(t0) {
		t.Errorf("claims = %+v", claims)
	}
	if !claims.HasScope("messages:send") || claims.HasScope("messages") || claims.HasScope("messages:send:any") || claims.HasScope("video:read") {
		t.Errorf("scopes = %v", claims.Scope)
	}
	// A scope that merely contains another is another: only whole elements count.
	longer, err := v.Verify(context.Background(), e.token("platform-api", "messages:send:any"))
	if err != nil || longer.HasScope("messages:send") || !longer.HasScope("messages:send:any") {
		t.Errorf("a longer scope counted as the shorter: %+v, %v", longer, err)
	}
}

func TestATokenForAnotherAPIIsRefusedWhoeverTheUserIs(t *testing.T) {
	e := newEnv(t)
	platform, video := e.verifier("platform-api"), e.verifier("video-api")
	forPlatform, forVideo := e.token("platform-api", "messages:send"), e.token("video-api", "video:read")
	if _, err := platform.Verify(context.Background(), forPlatform); err != nil {
		t.Fatal(err)
	}
	if _, err := video.Verify(context.Background(), forVideo); err != nil {
		t.Fatal(err)
	}
	refused(t, video, forPlatform, "a token for the platform at the video API")
	refused(t, platform, forVideo, "a token for the video API at the platform")
	refused(t, platform, e.token(issuer+"/oauth2/userinfo", "openid"), "a token for UserInfo")
	refused(t, platform, e.token("panels-web", "messages:send"), "a token whose audience is a client_id")
}

func TestOtherTokensOfTheProviderAreNotAccessTokens(t *testing.T) {
	e := newEnv(t)
	v := e.verifier("panels-web")
	id, err := e.signer.SignIDToken(port.IDTokenClaims{Subject: e.user, ClientID: "panels-web", Nonce: "n", AuthTime: t0, AMR: []string{"passkey"}, SessionID: "sid-1"})
	if err != nil {
		t.Fatal(err)
	}
	refused(t, v, id.Value, "an ID token, whose audience is the client's own")
	logout, err := e.signer.SignLogoutToken(port.LogoutClaims{Subject: e.user, ClientID: "panels-web", SessionID: "sid-1", JTI: "j"})
	if err != nil {
		t.Fatal(err)
	}
	refused(t, v, logout.Value, "a logout token")
}

func TestATokenIsRefusedForItsTimeIssuerSignatureAndHeader(t *testing.T) {
	e := newEnv(t)
	v := e.verifier("platform-api")
	token := e.token("platform-api", "messages:send")
	if _, err := v.Verify(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	// Five minutes, and the leeway after them.
	e.clock.Advance(5*time.Minute + 20*time.Second)
	if _, err := v.Verify(context.Background(), token); err != nil {
		t.Errorf("a token inside the leeway was refused: %v", err)
	}
	e.clock.Advance(20 * time.Second)
	refused(t, v, token, "an expired token")

	foreignRing, _ := newRing(t, "oidc-a", "oidc-a") // the same kid, another key
	other := signerOf(t, foreignRing, e.clock)
	foreign, _, err := other.SignOIDCAccessToken(port.OIDCAccessClaims{Subject: e.user, ClientID: "c", Audience: "platform-api", Scope: []string{"messages:send"}, SessionID: "s", GrantID: "g", AuthTime: t0})
	if err != nil {
		t.Fatal(err)
	}
	refused(t, v, foreign.Value, "a token signed by another key under the same kid")
	refused(t, e.verifier("platform-api", func(c *resourcecheck.Config) { c.Issuer = "https://evil.example.test" }), e.token("platform-api", "messages:send"), "another issuer")

	parts := strings.Split(e.token("platform-api", "messages:send"), ".")
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	for name, header := range map[string]string{
		"no signature algorithm":  `{"alg":"none","typ":"at+jwt","kid":"oidc-a"}`,
		"HS256 with a public key": `{"alg":"HS256","typ":"at+jwt","kid":"oidc-a"}`,
		"a key by reference":      `{"alg":"RS256","typ":"at+jwt","kid":"oidc-a","jku":"https://evil.example.test/jwks"}`,
		"a key inside":            `{"alg":"RS256","typ":"at+jwt","kid":"oidc-a","jwk":{"kty":"RSA"}}`,
		"a certificate":           `{"alg":"RS256","typ":"at+jwt","kid":"oidc-a","x5u":"https://evil.example.test/cert"}`,
		"a critical header":       `{"alg":"RS256","typ":"at+jwt","kid":"oidc-a","crit":["x"],"x":1}`,
		"the wrong type":          `{"alg":"RS256","typ":"JWT","kid":"oidc-a"}`,
		"no type":                 `{"alg":"RS256","kid":"oidc-a"}`,
		"no key id":               `{"alg":"RS256","typ":"at+jwt"}`,
		"a repeated name":         `{"alg":"RS256","typ":"at+jwt","kid":"oidc-a","kid":"oidc-a"}`,
	} {
		refused(t, v, enc(header)+"."+parts[1]+"."+parts[2], name)
	}
	refused(t, v, parts[0]+"."+parts[1]+".", "an empty signature")
	refused(t, v, parts[0]+"."+parts[1], "two parts")
	refused(t, v, "", "nothing")
	refused(t, v, strings.Repeat("a", 5000), "an oversized token")
	// A payload swapped under the original signature.
	forged := enc(`{"iss":"` + issuer + `","sub":"` + e.user.String() + `","aud":"platform-api","exp":4102444800,"iat":1,"jti":"x","client_id":"c","scope":"admin:all"}`)
	refused(t, v, parts[0]+"."+forged+"."+parts[2], "a forged payload")
}

func TestKeysAreFetchedOnceRotatedAndSurviveAnOutage(t *testing.T) {
	e := newEnv(t)
	v := e.verifier("platform-api")

	// No keys and no issuer: the service cannot tell, and says so.
	e.site.set(nil, http.StatusInternalServerError)
	if _, err := v.Verify(context.Background(), e.token("platform-api", "messages:send")); !errors.Is(err, resourcecheck.ErrIssuerUnavailable) {
		t.Fatalf("with no keys at all: %v", err)
	}
	jwks, err := e.ring.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	e.site.set(jwks, http.StatusOK)
	e.clock.Advance(time.Minute)
	for range 5 {
		if _, err := v.Verify(context.Background(), e.token("platform-api", "messages:send")); err != nil {
			t.Fatal(err)
		}
	}
	hits := e.site.requests()

	// A key the set does not know is looked for once, and not again until the interval has passed.
	strangerRing, _ := newRing(t, "oidc-z", "oidc-z")
	unknown := signerOf(t, strangerRing, e.clock)
	tok, _, err := unknown.SignOIDCAccessToken(port.OIDCAccessClaims{Subject: e.user, ClientID: "c", Audience: "platform-api", Scope: []string{"messages:send"}, SessionID: "s", GrantID: "g", AuthTime: t0})
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		// Refused either way: the first look finds no such key (invalid), the rest are too soon to look again (unavailable).
		if _, err := v.Verify(context.Background(), tok.Value); err == nil || !errors.Is(err, resourcecheck.ErrInvalidToken) && !errors.Is(err, resourcecheck.ErrIssuerUnavailable) {
			t.Errorf("an unknown key id: %v", err)
		}
	}
	if got := e.site.requests() - hits; got > 1 {
		t.Errorf("an unknown kid caused %d fetches in a row", got)
	}

	// Rotation: the issuer starts signing with a second key; the service finds it when the interval allows.
	e.files["oidc-b"] = keyFile(t, "oidc-b")
	both := ringOf(t, "oidc-b", e.files)
	merged, err := both.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	e.site.set(merged, http.StatusOK)
	e.clock.Advance(time.Minute)
	e.signer = signerOf(t, both, e.clock)
	if _, err := v.Verify(context.Background(), e.token("platform-api", "messages:send")); err != nil {
		t.Errorf("a token under the new key after the rotation: %v", err)
	}
	// An outage after that does not stop it from checking what it already knows.
	e.site.set(nil, http.StatusServiceUnavailable)
	e.clock.Advance(10 * time.Minute)
	if _, err := v.Verify(context.Background(), e.token("platform-api", "messages:send")); err != nil {
		t.Errorf("an outage of the issuer stopped a service that held its keys: %v", err)
	}
}

func TestRequireAnswersAsBearerTokensDo(t *testing.T) {
	e := newEnv(t)
	v := e.verifier("platform-api")
	var seen resourcecheck.Claims
	h := v.Require("messages:send")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen, _ = resourcecheck.FromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	call := func(mutate func(r *http.Request)) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/messages", nil)
		mutate(r)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	good := e.token("platform-api", "messages:read", "messages:send")

	if w := call(func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+good) }); w.Code != http.StatusNoContent || seen.Subject != e.user.String() {
		t.Errorf("a good token = %d, claims %+v", w.Code, seen)
	}
	if w := call(func(*http.Request) {}); w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Errorf("no token = %d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	if w := call(func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+e.token("video-api", "messages:send")) }); w.Code != http.StatusUnauthorized ||
		!strings.Contains(w.Header().Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Errorf("another API's token = %d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	if w := call(func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+e.token("platform-api", "messages:read"))
	}); w.Code != http.StatusForbidden ||
		!strings.Contains(w.Header().Get("WWW-Authenticate"), `error="insufficient_scope"`) {
		t.Errorf("a missing scope = %d %q", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	if w := call(func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+e.token("platform-api", "messages:send:any"))
	}); w.Code != http.StatusForbidden {
		t.Errorf("a similar scope = %d", w.Code)
	}
	// A token in the query or the body is not read; neither are two credentials, or another scheme.
	if w := call(func(r *http.Request) { r.URL.RawQuery = "access_token=" + good }); w.Code != http.StatusUnauthorized {
		t.Errorf("a token in the query = %d", w.Code)
	}
	if w := call(func(r *http.Request) {
		r.Header.Add("Authorization", "Bearer "+good)
		r.Header.Add("Authorization", "Bearer "+good)
	}); w.Code != http.StatusUnauthorized {
		t.Errorf("two credentials = %d", w.Code)
	}
	if w := call(func(r *http.Request) { r.Header.Set("Authorization", "Basic "+good) }); w.Code != http.StatusUnauthorized {
		t.Errorf("another scheme = %d", w.Code)
	}
	// Keys that cannot be had are an outage, not a refusal of the person.
	down := e.verifier("platform-api", func(c *resourcecheck.Config) { c.JWKSURL = e.site.srv.URL + "/missing" })
	r := httptest.NewRequest(http.MethodPost, "/messages", nil)
	r.Header.Set("Authorization", "Bearer "+good)
	w := httptest.NewRecorder()
	down.Require()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("an issuer without keys = %d", w.Code)
	}
}

func TestDiscoveryAndConfigurationAreStrict(t *testing.T) {
	e := newEnv(t)
	got, err := resourcecheck.Discover(context.Background(), nil, e.site.issuer)
	if err != nil || got != e.site.jwksURI {
		t.Fatalf("discover = %q, %v", got, err)
	}
	e.site.mu.Lock()
	e.site.issuer = "https://someone-else.example.test"
	e.site.mu.Unlock()
	if _, err := resourcecheck.Discover(context.Background(), nil, e.site.srv.URL); err == nil {
		t.Error("a document that names another issuer was believed")
	}
	e.site.mu.Lock()
	e.site.issuer, e.site.jwksURI = e.site.srv.URL, "http://169.254.169.254/keys"
	e.site.mu.Unlock()
	if _, err := resourcecheck.Discover(context.Background(), nil, e.site.srv.URL); err == nil {
		t.Error("a key set on another host was followed")
	}
	for name, cfg := range map[string]resourcecheck.Config{
		"no issuer":              {Audience: "a", JWKSURL: e.site.jwksURI},
		"no audience":            {Issuer: issuer, JWKSURL: e.site.jwksURI},
		"plain http, not local":  {Issuer: issuer, Audience: "a", JWKSURL: "http://auth.example.test/jwks"},
		"credentials in the url": {Issuer: issuer, Audience: "a", JWKSURL: "https://u:p@auth.example.test/jwks"},
		"a negative leeway":      {Issuer: issuer, Audience: "a", JWKSURL: e.site.jwksURI, Leeway: -time.Second},
	} {
		if _, err := resourcecheck.New(cfg); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// introspector is an issuer's introspection endpoint that answers what the test says.
type introspector struct {
	srv    *httptest.Server
	mu     sync.Mutex
	status int
	answer func(tok resourcecheck.Claims) map[string]any
	calls  int
	user   string
	pass   string
	body   url.Values
	claims resourcecheck.Claims
}

func newIntrospector(t *testing.T, e *env, audience string) *introspector {
	t.Helper()
	i := &introspector{status: http.StatusOK}
	i.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i.mu.Lock()
		defer i.mu.Unlock()
		i.calls++
		i.user, i.pass, _ = r.BasicAuth()
		_ = r.ParseForm()
		i.body = r.PostForm
		if i.status != http.StatusOK {
			w.WriteHeader(i.status)
			return
		}
		out := map[string]any{"active": true, "aud": audience, "sub": i.claims.Subject, "jti": i.claims.TokenID, "client_id": i.claims.ClientID, "scope": strings.Join(i.claims.Scope, " ")}
		if i.answer != nil {
			out = i.answer(i.claims)
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(i.srv.Close)
	return i
}

func TestIntrospectionMakesAnEndedGrantStopWorkingAtOnce(t *testing.T) {
	e := newEnv(t)
	in := newIntrospector(t, e, "platform-api")
	v := e.verifier("platform-api", func(c *resourcecheck.Config) {
		c.Introspection = &resourcecheck.Introspection{URL: in.srv.URL, ResourceID: "platform", Secret: "s3cret/+"}
	})
	token := e.token("platform-api", "messages:send")
	claims, err := v.Verify(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	in.claims = claims

	if _, err := v.Check(context.Background(), token); err != nil {
		t.Fatalf("a live token = %v", err)
	}
	if in.user != "platform" || in.pass != url.QueryEscape("s3cret/+") || in.body.Get("token") != token {
		t.Errorf("the request: user %q pass %q token sent %v", in.user, in.pass, in.body.Get("token") == token)
	}

	in.answer = func(resourcecheck.Claims) map[string]any { return map[string]any{"active": false} }
	if _, err := v.Check(context.Background(), token); !errors.Is(err, resourcecheck.ErrInvalidToken) {
		t.Errorf("a token the issuer ended = %v, want ErrInvalidToken", err)
	}
	// Offline checking is as it was: it cannot know.
	if _, err := v.Verify(context.Background(), token); err != nil {
		t.Errorf("Verify = %v", err)
	}
}

func TestAnIntrospectionThatCannotBeHadIsNeverAYes(t *testing.T) {
	e := newEnv(t)
	in := newIntrospector(t, e, "platform-api")
	v := e.verifier("platform-api", func(c *resourcecheck.Config) {
		c.Introspection = &resourcecheck.Introspection{URL: in.srv.URL, ResourceID: "platform", Secret: "x"}
	})
	token := e.token("platform-api", "messages:send")
	claims, _ := v.Verify(context.Background(), token)
	in.claims = claims

	for _, status := range []int{http.StatusInternalServerError, http.StatusUnauthorized, http.StatusFound} {
		in.status = status
		if _, err := v.Check(context.Background(), token); !errors.Is(err, resourcecheck.ErrIssuerUnavailable) {
			t.Errorf("status %d: %v, want ErrIssuerUnavailable", status, err)
		}
	}
	in.status = http.StatusOK
	// An active answer about another token (or another API) is not an answer about this one.
	for name, change := range map[string]func(map[string]any){
		"jti": func(m map[string]any) { m["jti"] = "another" }, "aud": func(m map[string]any) { m["aud"] = "video-api" },
		"sub": func(m map[string]any) { m["sub"] = "someone" }, "scope": func(m map[string]any) { m["scope"] = "messages:send admin:all" },
	} {
		in.answer = func(c resourcecheck.Claims) map[string]any {
			m := map[string]any{"active": true, "aud": "platform-api", "sub": c.Subject, "jti": c.TokenID, "client_id": c.ClientID, "scope": strings.Join(c.Scope, " ")}
			change(m)
			return m
		}
		if _, err := v.Check(context.Background(), token); !errors.Is(err, resourcecheck.ErrIssuerUnavailable) {
			t.Errorf("%s: %v, want ErrIssuerUnavailable", name, err)
		}
	}
	// Through Require: 503 when the issuer cannot say, 401 when it says no.
	h := v.Require("messages:send")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	call := func() int {
		r := httptest.NewRequest(http.MethodPost, "/m", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	in.status = http.StatusBadGateway
	if got := call(); got != http.StatusServiceUnavailable {
		t.Errorf("Require with no answer = %d", got)
	}
	in.status = http.StatusOK
	in.answer = func(resourcecheck.Claims) map[string]any { return map[string]any{"active": false} }
	if got := call(); got != http.StatusUnauthorized {
		t.Errorf("Require with a no = %d", got)
	}
}

func TestAnIntrospectionURLMustBeTrustedAndComplete(t *testing.T) {
	e := newEnv(t)
	for _, in := range []*resourcecheck.Introspection{
		{URL: "http://auth.example.com/introspect", ResourceID: "p", Secret: "s"},
		{URL: "https://user:pw@auth.example.com/introspect", ResourceID: "p", Secret: "s"},
		{URL: "https://auth.example.com/introspect", Secret: "s"},
		{URL: "https://auth.example.com/introspect", ResourceID: "p"},
	} {
		_, err := resourcecheck.New(resourcecheck.Config{Issuer: issuer, Audience: "platform-api", JWKSURL: e.site.jwksURI, Introspection: in})
		if err == nil {
			t.Errorf("%+v was accepted", in)
		}
	}
}

func TestAServiceTokenIsMarkedAndAnAPIForPeopleRefusesIt(t *testing.T) {
	e := newEnv(t)
	v := e.verifier("platform-api")
	svc, _, err := e.signer.SignServiceToken(port.ServiceAccessClaims{ClientID: "billing-worker", Audience: "platform-api", Scope: []string{"messages:send"}})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := v.Verify(context.Background(), svc.Value)
	if err != nil || !claims.Service || claims.Subject != "billing-worker" || claims.ClientID != "billing-worker" || claims.GrantID != "" || !claims.HasScope("messages:send") {
		t.Fatalf("service claims = %+v, %v", claims, err)
	}
	if person, err := v.Verify(context.Background(), e.token("platform-api", "messages:send")); err != nil || person.Service {
		t.Errorf("a person's token = %+v, %v", person, err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	call := func(h http.Handler, token string) int {
		r := httptest.NewRequest(http.MethodPost, "/m", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if got := call(v.Require("messages:send")(next), svc.Value); got != http.StatusNoContent {
		t.Errorf("Require with a service = %d", got)
	}
	people := v.RequireUser("messages:send")(next)
	if got := call(people, svc.Value); got != http.StatusForbidden {
		t.Errorf("RequireUser with a service = %d", got)
	}
	if got := call(people, e.token("platform-api", "messages:send")); got != http.StatusNoContent {
		t.Errorf("RequireUser with a person = %d", got)
	}
	if got := call(people, "garbage"); got != http.StatusUnauthorized {
		t.Errorf("RequireUser with garbage = %d", got)
	}
}
