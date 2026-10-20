package jwt_test

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"

	"go.airlance.org/auth/internal/adapter/jwt"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/testutil"
)

const (
	oidcIssuer = "https://auth.example.test"
	userInfoAu = "https://auth.example.test/oauth2/userinfo"
)

var oidcNow = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

type oidcFixture struct {
	t      *testing.T
	clock  *testutil.FakeClock
	tokens *jwt.OIDCTokens
	ring   *jwt.RSARing
	user   identity.UserID
}

func newOIDCFixture(t *testing.T) *oidcFixture {
	t.Helper()

	ring, err := jwt.LoadRSARing("oidc-a", map[string]string{"oidc-a": testutil.WriteFile(t, "a.pem", testutil.NewRSAKeyPEM(t).Private)})
	if err != nil {
		t.Fatal(err)
	}

	clock := testutil.NewFakeClock(oidcNow)

	tokens, err := jwt.NewOIDCTokens(ring, clock, oidcIssuer, 5*time.Minute, 5*time.Minute, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	user, err := identity.ParseUserID("00000000-0000-4000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}

	return &oidcFixture{t: t, clock: clock, tokens: tokens, ring: ring, user: user}
}

func (f *oidcFixture) accessClaims() port.OIDCAccessClaims {
	return port.OIDCAccessClaims{
		Subject: f.user, ClientID: "panels-web", Audience: userInfoAu, Scope: []string{"openid", "email"},
		SessionID: "0190a000-0000-7000-8000-000000000001", GrantID: "0190a000-0000-7000-8000-000000000002", AuthTime: oidcNow.Add(-time.Minute),
	}
}

func (f *oidcFixture) access() string {
	f.t.Helper()

	token, _, err := f.tokens.SignOIDCAccessToken(f.accessClaims())
	if err != nil {
		f.t.Fatal(err)
	}

	return token.Value
}

func TestAnOIDCAccessTokenRoundTrips(t *testing.T) {
	f := newOIDCFixture(t)

	token, made, err := f.tokens.SignOIDCAccessToken(f.accessClaims())
	if err != nil {
		t.Fatal(err)
	}

	got, err := f.tokens.VerifyOIDCAccess(token.Value, userInfoAu)
	if err != nil {
		t.Fatal(err)
	}

	if got.Subject != f.user || got.ClientID != "panels-web" || got.Audience != userInfoAu || strings.Join(got.Scope, " ") != "openid email" ||
		got.SessionID == "" || got.GrantID == "" || got.JTI == "" || got.JTI != made.JTI || !got.ExpiresAt.Equal(oidcNow.Add(5*time.Minute)) {
		t.Errorf("claims = %+v", got)
	}
	// Each token has its own identifier.
	other, _, _ := f.tokens.SignOIDCAccessToken(f.accessClaims())
	if other.Value == token.Value {
		t.Error("two tokens are identical")
	}

	// RFC 9068: the type header says what the token is, and the key is named by kid.
	parsed, err := josejwt.ParseSigned(token.Value, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}

	h := parsed.Headers[0]
	if h.KeyID != "oidc-a" || h.ExtraHeaders[jose.HeaderType] != "at+jwt" {
		t.Errorf("header = %+v", h)
	}
}

func TestAnIDTokenIsNotAnAccessToken(t *testing.T) {
	f := newOIDCFixture(t)

	id, err := f.tokens.SignIDToken(port.IDTokenClaims{
		Subject: f.user, ClientID: "panels-web", Nonce: "n", AuthTime: oidcNow, AMR: []string{"passkey"}, SessionID: "0190a000-0000-7000-8000-000000000001",
		IncludeEmail: true, Email: "alice@example.test", EmailVerified: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := f.tokens.VerifyOIDCAccess(id.Value, userInfoAu); !errors.Is(err, port.ErrInvalidOIDCToken) {
		t.Errorf("an ID token passed for an access token: %v", err)
	}
	// And the ID token carries what a client checks.
	parsed, _ := josejwt.ParseSigned(id.Value, []jose.SignatureAlgorithm{jose.RS256})

	var claims map[string]any
	if err := parsed.Claims(f.ring.PublicKeys()["oidc-a"], &claims); err != nil {
		t.Fatal(err)
	}

	if claims["aud"] != "panels-web" || claims["nonce"] != "n" || claims["email_verified"] != true || claims["iss"] != oidcIssuer {
		t.Errorf("claims = %v", claims)
	}
	// Without the email scope there is no email at all.
	plain, _ := f.tokens.SignIDToken(port.IDTokenClaims{Subject: f.user, ClientID: "panels-web", Nonce: "n", AuthTime: oidcNow, AMR: []string{"passkey"}, SessionID: "s"})
	parsed, _ = josejwt.ParseSigned(plain.Value, []jose.SignatureAlgorithm{jose.RS256})
	claims = nil

	_ = parsed.Claims(f.ring.PublicKeys()["oidc-a"], &claims)
	if _, ok := claims["email"]; ok {
		t.Error("an ID token for a grant without the email scope carries the email")
	}
}

func TestSigningRefusesIncompleteClaims(t *testing.T) {
	f := newOIDCFixture(t)

	c := f.accessClaims()
	for name, mutate := range map[string]func(*port.OIDCAccessClaims){
		"no audience": func(c *port.OIDCAccessClaims) { c.Audience = "" },
		"no scope":    func(c *port.OIDCAccessClaims) { c.Scope = nil },
		"no client":   func(c *port.OIDCAccessClaims) { c.ClientID = "" },
		"no grant":    func(c *port.OIDCAccessClaims) { c.GrantID = "" },
	} {
		bad := c
		mutate(&bad)

		if _, _, err := f.tokens.SignOIDCAccessToken(bad); err == nil {
			t.Errorf("%s: a token was signed", name)
		}
	}

	if _, err := f.tokens.SignIDToken(port.IDTokenClaims{Subject: f.user, ClientID: "x", AuthTime: oidcNow, AMR: []string{"a"}, SessionID: "s"}); err == nil {
		t.Error("an ID token without a nonce was signed")
	}
}

func TestOIDCAccessVerificationRefusals(t *testing.T) {
	f := newOIDCFixture(t)
	good := f.access()
	parts := strings.Split(good, ".")
	b64 := func(v any) string {
		data, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(data)
	}
	body, _ := base64.RawURLEncoding.DecodeString(parts[1])

	// A token signed by a key the provider does not publish.
	otherRing, _ := jwt.LoadRSARing("oidc-a", map[string]string{"oidc-a": testutil.WriteFile(t, "b.pem", rsaKey(t))})
	foreign, _ := jwt.NewOIDCTokens(otherRing, f.clock, oidcIssuer, time.Minute, 5*time.Minute, 30*time.Second)
	foreignToken, _, _ := foreign.SignOIDCAccessToken(f.accessClaims())

	// A token of another issuer, of another audience, and one made with the HMAC algorithm keyed by the public key
	// (the classic confusion): none may pass.
	wrongIssuer, _ := jwt.NewOIDCTokens(f.ring, f.clock, "https://other.example.test", time.Minute, 5*time.Minute, 30*time.Second)
	issuerToken, _, _ := wrongIssuer.SignOIDCAccessToken(f.accessClaims())
	audience := f.accessClaims()
	audience.Audience = "https://api.example.test"
	audienceToken, _, _ := f.tokens.SignOIDCAccessToken(audience)

	header := b64(map[string]any{"alg": "HS256", "typ": "at+jwt", "kid": "oidc-a"})
	mac := hmac.New(sha256.New, []byte("public-key-bytes"))
	mac.Write([]byte(header + "." + parts[1]))
	hmacToken := header + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	noneToken := b64(map[string]any{"alg": "none", "typ": "at+jwt", "kid": "oidc-a"}) + "." + parts[1] + "."

	cases := map[string]string{
		"garbage":              "a.b.c",
		"empty":                "",
		"json serialization":   `{"payload":"` + parts[1] + `","signature":"` + parts[2] + `"}`,
		"a space in it":        good + " ",
		"another key":          foreignToken.Value,
		"another issuer":       issuerToken.Value,
		"another audience":     audienceToken.Value,
		"the none algorithm":   noneToken,
		"HS256":                hmacToken,
		"a tampered body":      parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(strings.Replace(string(body), "panels-web", "panels-wex", 1))) + "." + parts[2],
		"a stripped signature": parts[0] + "." + parts[1] + ".",
		"an unknown kid":       b64(map[string]any{"alg": "RS256", "typ": "at+jwt", "kid": "other"}) + "." + parts[1] + "." + parts[2],
		"no kid":               b64(map[string]any{"alg": "RS256", "typ": "at+jwt"}) + "." + parts[1] + "." + parts[2],
		"a jwk header":         b64(map[string]any{"alg": "RS256", "typ": "at+jwt", "kid": "oidc-a", "jwk": map[string]any{"kty": "RSA"}}) + "." + parts[1] + "." + parts[2],
		"a jku header":         b64(map[string]any{"alg": "RS256", "typ": "at+jwt", "kid": "oidc-a", "jku": "https://evil.example/jwks"}) + "." + parts[1] + "." + parts[2],
		"the wrong type":       b64(map[string]any{"alg": "RS256", "typ": "JWT", "kid": "oidc-a"}) + "." + parts[1] + "." + parts[2],
	}
	for name, token := range cases {
		if _, err := f.tokens.VerifyOIDCAccess(token, userInfoAu); !errors.Is(err, port.ErrInvalidOIDCToken) {
			t.Errorf("%s: err = %v, want ErrInvalidOIDCToken", name, err)
		}
	}

	if _, err := f.tokens.VerifyOIDCAccess(good, "https://api.example.test"); !errors.Is(err, port.ErrInvalidOIDCToken) {
		t.Error("a token for UserInfo was accepted for another resource")
	}

	if _, err := f.tokens.VerifyOIDCAccess(good, ""); err == nil {
		t.Error("a token was accepted with no audience to check")
	}

	if _, err := f.tokens.VerifyOIDCAccess(good, userInfoAu); err != nil {
		t.Errorf("the genuine token was refused: %v", err)
	}

	// Time: valid inside the lifetime and the leeway, refused outside.
	f.clock.Advance(5*time.Minute + 20*time.Second)

	if _, err := f.tokens.VerifyOIDCAccess(good, userInfoAu); err != nil {
		t.Errorf("within the leeway: %v", err)
	}

	f.clock.Advance(20 * time.Second)

	if _, err := f.tokens.VerifyOIDCAccess(good, userInfoAu); !errors.Is(err, port.ErrInvalidOIDCToken) {
		t.Errorf("an expired token: %v", err)
	}
}

func TestOIDCKeyringRefusals(t *testing.T) {
	pem := testutil.NewRSAKeyPEM(t)
	ec := testutil.NewSigningKeyPEM(t)
	write := func(name string, data []byte) string { return testutil.WriteFile(t, name, data) }

	if _, err := jwt.LoadRSARing("a", map[string]string{"a": write("ec.pem", ec.Private)}); err == nil {
		t.Error("an ECDSA key was accepted as an RSA one")
	}

	if _, err := jwt.LoadRSARing("a", map[string]string{"a": write("pub.pem", pem.Public)}); err == nil {
		t.Error("a ring whose active key has no private half was accepted")
	}

	if _, err := jwt.LoadRSARing("b", map[string]string{"a": write("a.pem", pem.Private)}); err == nil {
		t.Error("an active kid that is not in the ring was accepted")
	}

	if _, err := jwt.LoadRSARing("a", map[string]string{"a": write("junk.pem", []byte("not a key"))}); err == nil {
		t.Error("junk was accepted as a key")
	}

	if _, err := jwt.LoadRSARing("a", nil); err == nil {
		t.Error("an empty ring was accepted")
	}
	// A retired key may be public only: it verifies what it signed and signs nothing.
	ring, err := jwt.LoadRSARing("a", map[string]string{"a": write("a.pem", pem.Private), "old": write("old.pem", pem.Public)})
	if err != nil {
		t.Fatal(err)
	}

	set, err := ring.JWKS()
	if err != nil {
		t.Fatal(err)
	}

	var keys jose.JSONWebKeySet
	if err := json.Unmarshal(set, &keys); err != nil || len(keys.Keys) != 2 {
		t.Fatalf("jwks = %s, %v", set, err)
	}

	for _, k := range keys.Keys {
		if !k.IsPublic() || k.Algorithm != "RS256" || k.Use != "sig" || k.KeyID == "" {
			t.Errorf("published key %+v", k)
		}
	}

	if strings.Contains(string(set), `"d"`) || strings.Contains(ring.String(), "PRIVATE") {
		t.Error("private material leaks")
	}
}

// rsaKey makes a second RSA private key file content, distinct from the shared one, for a "foreign signer".
func rsaKey(t *testing.T) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func TestALogoutTokenIsOnlyEverALogoutToken(t *testing.T) {
	f := newOIDCFixture(t)

	token, err := f.tokens.SignLogoutToken(port.LogoutClaims{Subject: f.user, ClientID: "panels-web", SessionID: "sid-1", JTI: "notice-1"})
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := josejwt.ParseSigned(token.Value, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}

	if h := parsed.Headers[0]; h.KeyID != "oidc-a" || h.ExtraHeaders[jose.HeaderType] != "logout+jwt" {
		t.Errorf("header = %+v", h)
	}

	var claims map[string]any
	if err := parsed.Claims(f.ring.PublicKeys()["oidc-a"], &claims); err != nil {
		t.Fatal(err)
	}

	events, _ := claims["events"].(map[string]any)
	if _, ok := events["http://schemas.openid.net/event/backchannel-logout"]; !ok || len(events) != 1 {
		t.Errorf("events = %v", claims["events"])
	}

	if claims["aud"] != "panels-web" || claims["sid"] != "sid-1" || claims["jti"] != "notice-1" || claims["iss"] != oidcIssuer || claims["sub"] != f.user.String() {
		t.Errorf("claims = %v", claims)
	}

	if _, ok := claims["nonce"]; ok {
		t.Error("a logout token must not carry a nonce")
	}

	if !token.ExpiresAt.Equal(oidcNow.Add(2 * time.Minute)) {
		t.Errorf("expires at %v, want two minutes after issue", token.ExpiresAt)
	}
	// It is neither of the other kinds.
	if _, err := f.tokens.VerifyOIDCAccess(token.Value, userInfoAu); !errors.Is(err, port.ErrInvalidOIDCToken) {
		t.Errorf("as an access token: %v", err)
	}

	if _, err := f.tokens.VerifyIDTokenHint(token.Value); !errors.Is(err, port.ErrInvalidOIDCToken) {
		t.Errorf("as an ID token hint: %v", err)
	}

	for name, bad := range map[string]port.LogoutClaims{
		"no session": {Subject: f.user, ClientID: "c", JTI: "j"}, "no client": {Subject: f.user, SessionID: "s", JTI: "j"}, "no jti": {Subject: f.user, ClientID: "c", SessionID: "s"},
	} {
		if _, err := f.tokens.SignLogoutToken(bad); err == nil {
			t.Errorf("%s: a token was signed", name)
		}
	}
}

func TestAnIDTokenHintIsCheckedButMayHaveExpired(t *testing.T) {
	f := newOIDCFixture(t)
	idToken := func(tokens *jwt.OIDCTokens) string {
		t.Helper()

		got, err := tokens.SignIDToken(port.IDTokenClaims{Subject: f.user, ClientID: "panels-web", Nonce: "n", AuthTime: oidcNow, AMR: []string{"passkey"}, SessionID: "sid-1"})
		if err != nil {
			t.Fatal(err)
		}

		return got.Value
	}
	good := idToken(f.tokens)

	hint, err := f.tokens.VerifyIDTokenHint(good)
	if err != nil || hint.Subject != f.user || hint.ClientID != "panels-web" || hint.SessionID != "sid-1" {
		t.Fatalf("hint = %+v, %v", hint, err)
	}

	f.clock.Advance(48 * time.Hour)

	if _, err := f.tokens.VerifyIDTokenHint(good); err != nil {
		t.Errorf("an expired ID token was refused as a hint: %v", err)
	}

	otherRing, _ := jwt.LoadRSARing("oidc-a", map[string]string{"oidc-a": testutil.WriteFile(t, "b.pem", rsaKey(t))})
	foreign, _ := jwt.NewOIDCTokens(otherRing, f.clock, oidcIssuer, time.Minute, time.Minute, 0)

	wrongIssuer, _ := jwt.NewOIDCTokens(f.ring, f.clock, "https://other.example.test", time.Minute, time.Minute, 0)
	for name, token := range map[string]string{
		"garbage": "a.b.c", "empty": "", "another key": idToken(foreign), "another issuer": idToken(wrongIssuer), "an access token": f.access(),
		"a tampered token": strings.Replace(good, "a", "b", 1)[:len(good)-3] + "AAA",
	} {
		if _, err := f.tokens.VerifyIDTokenHint(token); !errors.Is(err, port.ErrInvalidOIDCToken) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestAServiceTokenIsNeverAUsersAndAUsersIsNeverAServices(t *testing.T) {
	f := newOIDCFixture(t)

	svc, claims, err := f.tokens.SignServiceToken(port.ServiceAccessClaims{ClientID: "billing-worker", Audience: "platform-api", Scope: []string{"messages:send"}})
	if err != nil {
		t.Fatal(err)
	}

	if claims.JTI == "" || !claims.ExpiresAt.After(claims.IssuedAt) {
		t.Errorf("claims = %+v", claims)
	}

	got, err := f.tokens.VerifyServiceAccess(svc.Value, "platform-api")
	if err != nil || got.ClientID != "billing-worker" || strings.Join(got.Scope, " ") != "messages:send" || got.JTI != claims.JTI || got.Audience != "platform-api" {
		t.Fatalf("service claims = %+v, %v", got, err)
	}
	// The claims of a sign-in are not in it, and the subject is the client.
	payload := decodePayload(t, svc.Value)
	for _, k := range []string{"sid", "grant_id", "auth_time"} {
		if _, ok := payload[k]; ok {
			t.Errorf("a service token carries %s", k)
		}
	}

	if payload["sub"] != "billing-worker" || payload["client_id"] != "billing-worker" || payload["aud"] != "platform-api" {
		t.Errorf("payload = %v", payload)
	}
	// The user-token verifier refuses it, so UserInfo and the revocation endpoint never take it for a person's.
	if _, err := f.tokens.VerifyOIDCAccess(svc.Value, "platform-api"); !errors.Is(err, port.ErrInvalidOIDCToken) {
		t.Errorf("a user verifier took a service token: %v", err)
	}
	// And the service verifier refuses a user's.
	user, _, err := f.tokens.SignOIDCAccessToken(port.OIDCAccessClaims{
		Subject: f.user, ClientID: "panels-web", Audience: "platform-api", Scope: []string{"messages:send"},
		SessionID: "0190a000-0000-7000-8000-000000000001", GrantID: "0190a000-0000-7000-8000-000000000002", AuthTime: oidcNow,
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := f.tokens.VerifyServiceAccess(user.Value, "platform-api"); !errors.Is(err, port.ErrInvalidOIDCToken) {
		t.Errorf("a service verifier took a user's token: %v", err)
	}
	// Audience and time are checked as for any access token.
	if _, err := f.tokens.VerifyServiceAccess(svc.Value, "video-api"); !errors.Is(err, port.ErrInvalidOIDCToken) {
		t.Errorf("another audience: %v", err)
	}

	f.clock.Advance(time.Hour)

	if _, err := f.tokens.VerifyServiceAccess(svc.Value, "platform-api"); !errors.Is(err, port.ErrInvalidOIDCToken) {
		t.Errorf("an expired token: %v", err)
	}

	for name, c := range map[string]port.ServiceAccessClaims{
		"no client": {Audience: "a", Scope: []string{"x:y"}}, "no audience": {ClientID: "c", Scope: []string{"x:y"}}, "no scope": {ClientID: "c", Audience: "a"},
	} {
		if _, _, err := f.tokens.SignServiceToken(c); err == nil {
			t.Errorf("%s was signed", name)
		}
	}
}

func decodePayload(t *testing.T, token string) map[string]any {
	t.Helper()

	raw, err := base64.RawURLEncoding.DecodeString(strings.Split(token, ".")[1])
	if err != nil {
		t.Fatal(err)
	}

	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}

	return m
}
