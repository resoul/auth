package tokencheck_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"go.airlance.org/auth/examples/tokencheck"
	"go.airlance.org/auth/internal/adapter/jwt"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/session"
	"go.airlance.org/auth/internal/testutil"
)

const (
	issuer   = "https://auth.example.test"
	audience = "example"
)

var t0 = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

// issuerSite is the auth service as a product service sees it: a key set URL.
type issuerSite struct {
	t      *testing.T
	srv    *httptest.Server
	mu     sync.Mutex
	body   []byte
	status int
	hits   int
}

func newIssuerSite(t *testing.T, jwks []byte) *issuerSite {
	s := &issuerSite{t: t, body: jwks, status: http.StatusOK}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()

		s.hits++
		if s.status != http.StatusOK {
			w.WriteHeader(s.status)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(s.body)
	}))
	t.Cleanup(s.srv.Close)

	return s
}

func (s *issuerSite) set(body []byte, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.body, s.status = body, status
}

func (s *issuerSite) requests() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.hits
}

type env struct {
	t      *testing.T
	clock  *testutil.FakeClock
	site   *issuerSite
	signer *jwt.Signer
	ring   *jwt.Ring
	v      *tokencheck.Verifier
	user   identity.UserID
	sess   session.ID
}

func ringOf(t *testing.T, active string, kids ...string) *jwt.Ring {
	t.Helper()

	files := map[string]string{}
	for _, kid := range kids {
		files[kid] = testutil.WriteFile(t, kid+".pem", testutil.NewSigningKeyPEM(t).Private)
	}

	ring, err := jwt.LoadRing(active, files)
	if err != nil {
		t.Fatal(err)
	}

	return ring
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, clock: testutil.NewFakeClock(t0), ring: ringOf(t, "sign-a", "sign-a")}

	jwks, err := e.ring.JWKS()
	if err != nil {
		t.Fatal(err)
	}

	e.site = newIssuerSite(t, jwks)
	if e.signer, err = jwt.NewSigner(e.ring, e.clock, issuer, audience, 5*time.Minute); err != nil {
		t.Fatal(err)
	}

	e.v = e.verifier(tokencheck.Config{Issuer: issuer, Audience: audience})
	f := testutil.NewFactory(t, t0)
	e.user = f.User(testutil.UserSpec{}).ID()
	e.sess = f.Session(testutil.SessionSpec{User: f.User(testutil.UserSpec{})}).ID()

	return e
}

func (e *env) verifier(cfg tokencheck.Config) *tokencheck.Verifier {
	e.t.Helper()
	cfg.JWKSURL, cfg.Now = e.site.srv.URL, e.clock.Now

	v, err := tokencheck.New(cfg)
	if err != nil {
		e.t.Fatal(err)
	}

	return v
}

func (e *env) token() string {
	e.t.Helper()

	tok, err := e.signer.SignAccess(port.AccessClaims{UserID: e.user, SessionID: e.sess, AuthTime: t0, AMR: []string{"otp"}})
	if err != nil {
		e.t.Fatal(err)
	}

	return tok.Value
}

func (e *env) verify(token string) (tokencheck.Claims, error) {
	return e.v.Verify(context.Background(), token)
}

func (e *env) wantRefused(token, why string) {
	e.t.Helper()

	if _, err := e.verify(token); !errors.Is(err, tokencheck.ErrInvalidToken) {
		e.t.Errorf("%s: error = %v, want ErrInvalidToken", why, err)
	}
}

func TestVerifyReturnsTheClaimsOfARealToken(t *testing.T) {
	e := newEnv(t)

	claims, err := e.verify(e.token())
	if err != nil {
		t.Fatal(err)
	}

	if claims.Subject != e.user.String() || claims.SessionID != e.sess.String() || len(claims.AMR) != 1 || claims.AMR[0] != "otp" ||
		!claims.AuthTime.Equal(t0) || !claims.IssuedAt.Equal(t0) || !claims.ExpiresAt.Equal(t0.Add(5*time.Minute)) {
		t.Errorf("claims = %+v", claims)
	}

	if claims.ExpiresAt.Location() != time.UTC {
		t.Errorf("time zone %v, want UTC", claims.ExpiresAt.Location())
	}
}

func TestVerifyChecksTimeWithLeeway(t *testing.T) {
	e := newEnv(t)
	tok := e.token()
	e.clock.Advance(5*time.Minute + 29*time.Second)

	if _, err := e.verify(tok); err != nil {
		t.Errorf("within the leeway: %v", err)
	}

	e.clock.Advance(2 * time.Second)
	e.wantRefused(tok, "past the leeway")

	// A token from the future beyond the skew.
	future := newEnv(t)
	issued := future.token()
	future.clock.Set(t0.Add(-time.Minute))
	future.wantRefused(issued, "issued in the future")
}

func TestVerifyTrustsOnlyItsOwnIssuerAndAudience(t *testing.T) {
	e := newEnv(t)

	tok := e.token()
	for name, cfg := range map[string]tokencheck.Config{
		"another issuer":   {Issuer: "https://evil.example", Audience: audience},
		"another audience": {Issuer: issuer, Audience: "another-product"},
	} {
		v := e.verifier(cfg)
		if _, err := v.Verify(context.Background(), tok); !errors.Is(err, tokencheck.ErrInvalidToken) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
}

// crafted signs claims with a key of the test's own, published under kid.
type crafted struct {
	t    *testing.T
	key  *ecdsa.PrivateKey
	kid  string
	site *issuerSite
	v    *tokencheck.Verifier
}

func newCrafted(t *testing.T) *crafted {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	c := &crafted{t: t, key: key, kid: "k1"}

	set, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Use: "sig", Algorithm: "ES256"}}})
	if err != nil {
		t.Fatal(err)
	}

	c.site = newIssuerSite(t, set)

	c.v, err = tokencheck.New(tokencheck.Config{Issuer: issuer, Audience: audience, JWKSURL: c.site.srv.URL, Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}

	return c
}

func goodClaims() map[string]any {
	return map[string]any{
		"iss": issuer, "aud": []string{audience}, "sub": "user-1", "sid": "session-1",
		"iat": t0.Unix(), "exp": t0.Add(time.Minute).Unix(), "auth_time": t0.Unix(), "amr": []string{"otp"},
	}
}

func (c *crafted) sign(alg jose.SignatureAlgorithm, key any, opts *jose.SignerOptions, claims map[string]any) string {
	c.t.Helper()

	s, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		c.t.Fatal(err)
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		c.t.Fatal(err)
	}

	obj, err := s.Sign(payload)
	if err != nil {
		c.t.Fatal(err)
	}

	out, err := obj.CompactSerialize()
	if err != nil {
		c.t.Fatal(err)
	}

	return out
}

func (c *crafted) es256(typ string, kid string, claims map[string]any) string {
	c.t.Helper()

	opts := (&jose.SignerOptions{}).WithType(jose.ContentType(typ))

	return c.sign(jose.ES256, jose.JSONWebKey{Key: c.key, KeyID: kid}, opts, claims)
}

func (c *crafted) wantRefused(token, why string) {
	c.t.Helper()

	if _, err := c.v.Verify(context.Background(), token); !errors.Is(err, tokencheck.ErrInvalidToken) {
		c.t.Errorf("%s: error = %v, want ErrInvalidToken", why, err)
	}
}

func b64(v any) string {
	data, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(data)
}

func TestVerifyRefusesTokensThatAreNotWellFormedAccessTokens(t *testing.T) {
	c := newCrafted(t)
	if _, err := c.v.Verify(context.Background(), c.es256("at+jwt", "k1", goodClaims())); err != nil {
		t.Fatalf("the control token is refused: %v", err)
	}

	hmacKey := []byte("0123456789abcdef0123456789abcdef")

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	withoutClaim := func(name string) map[string]any {
		m := goodClaims()
		delete(m, name)

		return m
	}
	valid := c.es256("at+jwt", "k1", goodClaims())
	parts := strings.Split(valid, ".")

	for name, token := range map[string]string{
		"empty":                         "",
		"not a token":                   "abc",
		"oversized":                     strings.Repeat("a", 5000),
		"alg none":                      b64(map[string]string{"alg": "none", "typ": "at+jwt", "kid": "k1"}) + "." + b64(goodClaims()) + ".",
		"HS256 with the public key":     c.sign(jose.HS256, hmacKey, (&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", "k1"), goodClaims()),
		"RS256":                         c.sign(jose.RS256, rsaKey, (&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", "k1"), goodClaims()),
		"another type":                  c.es256("JWT", "k1", goodClaims()),
		"no type":                       c.es256("", "k1", goodClaims()),
		"no kid":                        c.es256("at+jwt", "", goodClaims()),
		"unknown kid":                   c.es256("at+jwt", "other", goodClaims()),
		"tampered claims":               parts[0] + "." + b64(map[string]any{"iss": issuer, "aud": []string{audience}, "sub": "admin", "sid": "s", "iat": t0.Unix(), "exp": t0.Add(time.Hour).Unix(), "auth_time": t0.Unix(), "amr": []string{"otp"}}) + "." + parts[2],
		"tampered signature":            parts[0] + "." + parts[1] + "." + tamper(parts[2]),
		"no subject":                    c.es256("at+jwt", "k1", withoutClaim("sub")),
		"no session":                    c.es256("at+jwt", "k1", withoutClaim("sid")),
		"no methods":                    c.es256("at+jwt", "k1", withoutClaim("amr")),
		"no auth time":                  c.es256("at+jwt", "k1", withoutClaim("auth_time")),
		"no expiry":                     c.es256("at+jwt", "k1", withoutClaim("exp")),
		"no issue time":                 c.es256("at+jwt", "k1", withoutClaim("iat")),
		"an embedded key in the header": embedKey(t, c),
		"a crit header":                 headerWith(t, c, "crit", []string{"exp"}),
		"a key URL in the header":       headerWith(t, c, "jku", "https://evil.example/keys"),
		"a repeated header":             repeatedHeader(valid),
	} {
		c.wantRefused(token, name)
	}
}

func embedKey(t *testing.T, c *crafted) string {
	t.Helper()

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	jwk := jose.JSONWebKey{Key: &other.PublicKey, KeyID: "k1"}
	opts := (&jose.SignerOptions{EmbedJWK: true}).WithType("at+jwt")

	return c.sign(jose.ES256, jose.JSONWebKey{Key: other, KeyID: jwk.KeyID}, opts, goodClaims())
}

func headerWith(t *testing.T, c *crafted, name string, value any) string {
	t.Helper()

	opts := (&jose.SignerOptions{}).WithType("at+jwt").WithHeader(jose.HeaderKey(name), value)

	return c.sign(jose.ES256, jose.JSONWebKey{Key: c.key, KeyID: "k1"}, opts, goodClaims())
}

// repeatedHeader repeats alg in the protected header: parsers disagree on which one counts.
func repeatedHeader(valid string) string {
	parts := strings.Split(valid, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	repeated := strings.TrimSuffix(string(raw), "}") + `,"alg":"ES256"}`

	return base64.RawURLEncoding.EncodeToString([]byte(repeated)) + "." + parts[1] + "." + parts[2]
}

func TestAKeyOfAnotherTypeInTheSetCannotVerifyAccessTokens(t *testing.T) {
	c := newCrafted(t)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	set, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &rsaKey.PublicKey, KeyID: "k1", Use: "sig"},
		{Key: &p384.PublicKey, KeyID: "k2", Use: "sig"},
		{Key: &c.key.PublicKey, KeyID: "k3", Use: "enc"},
		{Key: &c.key.PublicKey, KeyID: "k4", Use: "sig", Algorithm: "RS256"},
	}})
	if err != nil {
		t.Fatal(err)
	}

	c.site.set(set, http.StatusOK)

	_, err = c.v.Verify(context.Background(), c.es256("at+jwt", "k1", goodClaims()))
	if err == nil || errors.Is(err, tokencheck.ErrInvalidToken) {
		t.Errorf("error = %v: a set with no usable key is a failure to reach keys, not a bad token", err)
	}
}

func TestKeysAreCachedAndRotationIsFollowedWithoutHammeringTheIssuer(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 2; i++ {
		if _, err := e.verify(e.token()); err != nil {
			t.Fatal(err)
		}
	}

	if e.site.requests() != 1 {
		t.Fatalf("%d key set requests for two tokens, want 1", e.site.requests())
	}

	// The issuer adds a key and starts signing with it.
	rotated := ringOf(t, "sign-b", "sign-b")

	newSigner, err := jwt.NewSigner(rotated, e.clock, issuer, audience, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	jwks, err := rotated.JWKS()
	if err != nil {
		t.Fatal(err)
	}

	e.site.set(jwks, http.StatusOK)

	tok, err := newSigner.SignAccess(port.AccessClaims{UserID: e.user, SessionID: e.sess, AuthTime: t0, AMR: []string{"otp"}})
	if err != nil {
		t.Fatal(err)
	}

	// Too soon after the last fetch: the unknown kid does not trigger another request.
	e.clock.Advance(10 * time.Second)
	e.wantRefused(tok.Value, "an unknown kid inside the refetch spacing")

	if e.site.requests() != 1 {
		t.Errorf("%d requests, want still 1", e.site.requests())
	}
	// After the spacing the set is fetched once and the new key works.
	e.clock.Advance(25 * time.Second)

	if _, err := e.verify(tok.Value); err != nil {
		t.Errorf("a token of the new key: %v", err)
	}

	if e.site.requests() != 2 {
		t.Errorf("%d requests, want 2", e.site.requests())
	}
}

func TestAFloodOfUnknownKeyIDsMakesOneRequest(t *testing.T) {
	c := newCrafted(t)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			_, _ = c.v.Verify(context.Background(), c.es256("at+jwt", "random-"+string(rune('a'+i%26)), goodClaims()))
		}()
	}

	wg.Wait()

	if c.site.requests() != 1 {
		t.Errorf("%d key set requests for 100 unknown key ids, want 1", c.site.requests())
	}
}

func TestAKeyRemovedFromTheSetStopsWorkingAfterTheCacheExpires(t *testing.T) {
	e := newEnv(t)

	tok := e.token()
	if _, err := e.verify(tok); err != nil {
		t.Fatal(err)
	}

	other := ringOf(t, "sign-z", "sign-z")

	jwks, err := other.JWKS()
	if err != nil {
		t.Fatal(err)
	}

	e.site.set(jwks, http.StatusOK)

	e.clock.Advance(4 * time.Minute) // within the cache: the old key still verifies

	fresh := e.token()
	if _, err := e.verify(fresh); err != nil {
		t.Errorf("inside the cache lifetime: %v", err)
	}

	e.clock.Advance(2 * time.Minute) // past MaxKeyAge: the set is refreshed and the key is gone
	e.wantRefused(e.token(), "a key the issuer withdrew")
}

func TestAnIssuerOutageKeepsKnownKeysButNeverInventsOne(t *testing.T) {
	e := newEnv(t)
	if _, err := e.verify(e.token()); err != nil {
		t.Fatal(err)
	}

	e.site.set(nil, http.StatusInternalServerError)
	e.clock.Advance(time.Hour)

	if _, err := e.verify(e.token()); err != nil {
		t.Errorf("during the outage: %v", err)
	}

	// A verifier that never got a key set cannot decide: that is not a 401.
	down := newEnv(t)
	down.site.set(nil, http.StatusInternalServerError)

	if _, err := down.verify(down.token()); err == nil || errors.Is(err, tokencheck.ErrInvalidToken) {
		t.Errorf("error = %v, want a failure to reach the keys", err)
	}
}

func TestNewChecksTheConfiguration(t *testing.T) {
	ok := tokencheck.Config{Issuer: issuer, Audience: audience, JWKSURL: "https://auth.example.test/.well-known/jwks.json"}
	if _, err := tokencheck.New(ok); err != nil {
		t.Fatalf("a valid configuration: %v", err)
	}

	for name, mod := range map[string]func(*tokencheck.Config){
		"no issuer":            func(c *tokencheck.Config) { c.Issuer = "" },
		"no audience":          func(c *tokencheck.Config) { c.Audience = "" },
		"no URL":               func(c *tokencheck.Config) { c.JWKSURL = "" },
		"plain http, remote":   func(c *tokencheck.Config) { c.JWKSURL = "http://auth.example.test/jwks" },
		"credentials in a URL": func(c *tokencheck.Config) { c.JWKSURL = "https://u:p@auth.example.test/jwks" },
		"negative leeway":      func(c *tokencheck.Config) { c.Leeway = -time.Second },
	} {
		c := ok
		mod(&c)

		if _, err := tokencheck.New(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}

	for _, loopback := range []string{"http://127.0.0.1:8080/jwks", "http://localhost:8080/jwks", "http://[::1]:8080/jwks"} {
		c := ok

		c.JWKSURL = loopback
		if _, err := tokencheck.New(c); err != nil {
			t.Errorf("%s refused: %v", loopback, err)
		}
	}
}

// tamper changes the last two characters of a base64url signature. A fixed replacement would leave a
// signature that already ended with it intact, and the test would pass or fail by chance.
func tamper(signature string) string {
	head, tail := signature[:len(signature)-2], signature[len(signature)-2:]
	if tail == "AA" {
		return head + "BB"
	}

	return head + "AA"
}
