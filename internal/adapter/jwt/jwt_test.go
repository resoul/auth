package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"

	"go.airlance.org/auth/internal/adapter/jwt"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/session"
	"go.airlance.org/auth/internal/testutil"
)

const (
	issuer   = "https://auth.example.test"
	audience = "example"
	leeway   = 30 * time.Second
)

var t0 = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

// world is one signing key, its ring, a signer and a verifier on a fake clock.
type world struct {
	t        *testing.T
	clock    *testutil.FakeClock
	pem      testutil.SigningKeyPEM
	ring     *jwt.Ring
	signer   *jwt.Signer
	verifier *jwt.Verifier
	claims   port.AccessClaims
}

func newWorld(t *testing.T) *world {
	t.Helper()
	key := testutil.NewSigningKeyPEM(t)

	ring, err := jwt.LoadRing("sign-a", map[string]string{"sign-a": testutil.WriteFile(t, "a.pem", key.Private)})
	if err != nil {
		t.Fatalf("LoadRing: %v", err)
	}

	clock := testutil.NewFakeClock(t0)

	signer, err := jwt.NewSigner(ring, clock, issuer, audience, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := jwt.NewVerifier(ring.PublicKeys(), clock, issuer, audience, leeway)
	if err != nil {
		t.Fatal(err)
	}

	f := testutil.NewFactory(t, t0)
	user := f.User(testutil.UserSpec{})
	sess := f.Session(testutil.SessionSpec{User: user})

	return &world{
		t: t, clock: clock, pem: key, ring: ring, signer: signer, verifier: verifier,
		claims: port.AccessClaims{UserID: user.ID(), SessionID: sess.ID(), AuthTime: t0.Add(-time.Minute), AMR: []string{"otp"}},
	}
}

func (w *world) token() string {
	w.t.Helper()

	tok, err := w.signer.SignAccess(w.claims)
	if err != nil {
		w.t.Fatalf("SignAccess: %v", err)
	}

	return tok.Value
}

func TestSignedTokenVerifiesAndCarriesTheClaims(t *testing.T) {
	w := newWorld(t)

	tok, err := w.signer.SignAccess(w.claims)
	if err != nil {
		t.Fatalf("SignAccess: %v", err)
	}

	if !tok.ExpiresAt.Equal(t0.Add(5 * time.Minute)) {
		t.Errorf("ExpiresAt = %v", tok.ExpiresAt)
	}

	got, err := w.verifier.VerifyAccess(tok.Value)
	if err != nil {
		t.Fatalf("VerifyAccess: %v", err)
	}

	if got.UserID != w.claims.UserID || got.SessionID != w.claims.SessionID || len(got.AMR) != 1 || got.AMR[0] != "otp" {
		t.Errorf("claims = %+v", got)
	}

	if !got.AuthTime.Equal(w.claims.AuthTime) || !got.IssuedAt.Equal(t0) || !got.ExpiresAt.Equal(t0.Add(5*time.Minute)) {
		t.Errorf("times = auth %v iat %v exp %v", got.AuthTime, got.IssuedAt, got.ExpiresAt)
	}
}

func TestTokenShape(t *testing.T) {
	w := newWorld(t)
	parts := strings.Split(w.token(), ".")
	decode := func(i int) map[string]any {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			t.Fatal(err)
		}

		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}

		return m
	}
	header, claims := decode(0), decode(1)

	if header["alg"] != "ES256" || header["typ"] != "at+jwt" || header["kid"] != "sign-a" || len(header) != 3 {
		t.Errorf("header = %v", header)
	}

	for _, name := range []string{"iss", "sub", "aud", "exp", "iat", "sid", "auth_time", "amr"} {
		if _, ok := claims[name]; !ok {
			t.Errorf("claim %s is missing: %v", name, claims)
		}
	}

	for _, name := range []string{"email", "ip", "user_agent", "name", "nbf"} {
		if _, ok := claims[name]; ok {
			t.Errorf("claim %s must not be present", name)
		}
	}
}

func TestVerifierTimeBounds(t *testing.T) {
	w := newWorld(t)
	token := w.token() // iat t0, exp t0+5m

	tests := []struct {
		name string
		at   time.Time
		ok   bool
	}{
		{"just issued", t0, true},
		{"just before expiry", t0.Add(5*time.Minute - time.Second), true},
		{"inside the leeway after expiry", t0.Add(5*time.Minute + leeway - time.Second), true},
		{"past expiry and leeway", t0.Add(5*time.Minute + leeway + time.Second), false},
		{"long expired", t0.Add(24 * time.Hour), false},
		{"issued slightly in the future", t0.Add(-leeway + time.Second), true},
		{"issued too far in the future", t0.Add(-leeway - time.Second), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w.clock.Set(tt.at)

			_, err := w.verifier.VerifyAccess(token)
			if tt.ok && err != nil {
				t.Errorf("rejected: %v", err)
			}

			if !tt.ok && !isInvalid(err) {
				t.Errorf("accepted, or wrong error: %v", err)
			}
		})
	}
}

func isInvalid(err error) bool {
	return err != nil && strings.Contains(err.Error(), port.ErrInvalidAccessToken.Error())
}

// forge signs arbitrary claims and headers so that single properties can be broken.
type forge struct {
	key     *ecdsa.PrivateKey
	kid     string
	typ     string
	headers map[jose.HeaderKey]any
}

func (f forge) sign(t *testing.T, claims map[string]any) string {
	t.Helper()

	opts := (&jose.SignerOptions{}).WithType(jose.ContentType(f.typ))
	for k, v := range f.headers {
		opts = opts.WithHeader(k, v)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: f.key, KeyID: f.kid}}, opts)
	if err != nil {
		t.Fatal(err)
	}

	tok, err := josejwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}

	return tok
}

func (w *world) validClaims() map[string]any {
	return map[string]any{
		"iss": issuer, "sub": w.claims.UserID.String(), "aud": []string{audience},
		"iat": t0.Unix(), "exp": t0.Add(5 * time.Minute).Unix(),
		"sid": w.claims.SessionID.String(), "auth_time": t0.Unix(), "amr": []string{"otp"},
	}
}

func (w *world) activeKey() *ecdsa.PrivateKey {
	w.t.Helper()
	block, _ := pem.Decode(w.pem.Private)

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		w.t.Fatal(err)
	}

	return parsed.(*ecdsa.PrivateKey)
}

func (w *world) good() forge { return forge{key: w.activeKey(), kid: "sign-a", typ: "at+jwt"} }

func TestForgedBaselineIsAccepted(t *testing.T) {
	w := newWorld(t)
	if _, err := w.verifier.VerifyAccess(w.good().sign(t, w.validClaims())); err != nil {
		t.Fatalf("the forge helper must produce a valid token when nothing is broken: %v", err)
	}
}

func TestVerifierRejectsBrokenClaims(t *testing.T) {
	w := newWorld(t)
	mutate := func(f func(map[string]any)) string {
		c := w.validClaims()
		f(c)

		return w.good().sign(t, c)
	}

	tests := map[string]string{
		"wrong issuer":         mutate(func(c map[string]any) { c["iss"] = "https://evil.example.test" }),
		"wrong audience":       mutate(func(c map[string]any) { c["aud"] = []string{"other"} }),
		"audience as string":   mutate(func(c map[string]any) { c["aud"] = "other" }),
		"empty audience":       mutate(func(c map[string]any) { c["aud"] = []string{} }),
		"missing issuer":       mutate(func(c map[string]any) { delete(c, "iss") }),
		"missing subject":      mutate(func(c map[string]any) { delete(c, "sub") }),
		"missing audience":     mutate(func(c map[string]any) { delete(c, "aud") }),
		"missing exp":          mutate(func(c map[string]any) { delete(c, "exp") }),
		"missing iat":          mutate(func(c map[string]any) { delete(c, "iat") }),
		"missing sid":          mutate(func(c map[string]any) { delete(c, "sid") }),
		"missing auth_time":    mutate(func(c map[string]any) { delete(c, "auth_time") }),
		"missing amr":          mutate(func(c map[string]any) { delete(c, "amr") }),
		"empty amr":            mutate(func(c map[string]any) { c["amr"] = []string{} }),
		"blank amr entry":      mutate(func(c map[string]any) { c["amr"] = []string{"otp", ""} }),
		"subject is not an id": mutate(func(c map[string]any) { c["sub"] = "alice@example.test" }),
		"sid is not an id":     mutate(func(c map[string]any) { c["sid"] = "nope" }),
		"sid is a user id":     mutate(func(c map[string]any) { c["sid"] = w.claims.UserID.String() }),
		"exp not after iat":    mutate(func(c map[string]any) { c["exp"] = t0.Unix() }),
		"not yet valid (nbf)":  mutate(func(c map[string]any) { c["nbf"] = t0.Add(time.Hour).Unix() }),
		"expired":              mutate(func(c map[string]any) { c["exp"] = t0.Add(-time.Hour).Unix(); c["iat"] = t0.Add(-2 * time.Hour).Unix() }),
	}
	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := w.verifier.VerifyAccess(token); !isInvalid(err) {
				t.Errorf("accepted or wrong error: %v", err)
			}
		})
	}
}

func TestVerifierAcceptsAnAudienceListThatContainsOurs(t *testing.T) {
	w := newWorld(t)
	c := w.validClaims()

	c["aud"] = []string{"other", audience}
	if _, err := w.verifier.VerifyAccess(w.good().sign(t, c)); err != nil {
		t.Errorf("rejected: %v", err)
	}
}

func TestVerifierRejectsBrokenHeadersAndKeys(t *testing.T) {
	w := newWorld(t)
	claims := w.validClaims()

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	signWith := func(alg jose.SignatureAlgorithm, key any, kid string) string {
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: jose.JSONWebKey{Key: key, KeyID: kid}}, (&jose.SignerOptions{}).WithType("at+jwt"))
		if err != nil {
			t.Fatal(err)
		}

		tok, err := josejwt.Signed(signer).Claims(claims).Serialize()
		if err != nil {
			t.Fatal(err)
		}

		return tok
	}
	withHeader := func(k jose.HeaderKey, v any) string {
		f := w.good()
		f.headers = map[jose.HeaderKey]any{k: v}

		return f.sign(t, claims)
	}

	// HS256 keyed with the public key, the classic algorithm confusion attack.
	pubDER, err := x509.MarshalPKIXPublicKey(&w.activeKey().PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	hsHeader := b64([]byte(`{"alg":"HS256","typ":"at+jwt","kid":"sign-a"}`))
	payload, _ := json.Marshal(claims)
	signingInput := hsHeader + "." + b64(payload)
	mac := hmac.New(sha256.New, pubDER)
	mac.Write([]byte(signingInput))
	hs256 := signingInput + "." + b64(mac.Sum(nil))

	noneHeader := b64([]byte(`{"alg":"none","typ":"at+jwt","kid":"sign-a"}`))
	none := noneHeader + "." + b64(payload) + "."

	good := w.token()
	parts := strings.Split(good, ".")
	flip := func(s string) string {
		if s[0] == 'A' {
			return "B" + s[1:]
		}

		return "A" + s[1:]
	}

	dupHeader := b64([]byte(`{"alg":"ES256","typ":"at+jwt","kid":"sign-a","kid":"sign-a"}`))
	// A real signature over a header with a repeated name would still be refused.
	dupSigned := dupHeader + "." + parts[1] + "." + parts[2]

	badFormats := []string{"", "x", "a.b", "a.b.c.d", " " + good, good + "\n", good + " ", `{"payload":"x","signatures":[]}`}

	tests := map[string]string{
		"alg none":                        none,
		"HS256 keyed with the public key": hs256,
		"ES384":                           signWith(jose.ES384, p384, "sign-a"),
		"RS256":                           signWith(jose.RS256, rsaKey, "sign-a"),
		"signed by another key":           signWith(jose.ES256, otherKey, "sign-a"),
		"unknown kid":                     signWith(jose.ES256, w.activeKey(), "sign-z"),
		"no kid":                          signWith(jose.ES256, w.activeKey(), ""),
		"tampered payload":                parts[0] + "." + flip(parts[1]) + "." + parts[2],
		"tampered signature":              parts[0] + "." + parts[1] + "." + flip(parts[2]),
		"tampered header":                 flip(parts[0]) + "." + parts[1] + "." + parts[2],
		"repeated header name":            dupSigned,
		"typ JWT":                         forge{key: w.activeKey(), kid: "sign-a", typ: "JWT"}.sign(t, claims),
		"typ missing":                     forge{key: w.activeKey(), kid: "sign-a"}.sign(t, claims),
		"typ in another case":             forge{key: w.activeKey(), kid: "sign-a", typ: "AT+JWT"}.sign(t, claims),
		"jku header":                      withHeader("jku", "https://evil.example.test/keys"),
		"x5u header":                      withHeader("x5u", "https://evil.example.test/cert"),
		"crit header":                     withHeader("crit", []string{"exp"}),
		"embedded jwk":                    withHeader("jwk", map[string]any{"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"}),
		"x5t header":                      withHeader("x5t", "abc"),
	}
	for _, in := range badFormats {
		tests["format "+in] = in
	}

	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := w.verifier.VerifyAccess(token); !isInvalid(err) {
				t.Errorf("accepted or wrong error: %v", err)
			}
		})
	}
}

func TestVerifierErrorsDoNotEchoTheToken(t *testing.T) {
	w := newWorld(t)
	token := w.token()
	broken := token[:len(token)-4] + "AAAA"

	_, err := w.verifier.VerifyAccess(broken)
	if err == nil || strings.Contains(err.Error(), broken) || strings.Contains(err.Error(), strings.Split(token, ".")[1]) {
		t.Errorf("error %v echoes the token", err)
	}
}

func TestSignerRefusesIncompleteClaims(t *testing.T) {
	w := newWorld(t)
	for name, mutate := range map[string]func(*port.AccessClaims){
		"no user":      func(c *port.AccessClaims) { c.UserID = identity.UserID{} },
		"no session":   func(c *port.AccessClaims) { c.SessionID = session.ID{} },
		"no auth time": func(c *port.AccessClaims) { c.AuthTime = time.Time{} },
		"no methods":   func(c *port.AccessClaims) { c.AMR = nil },
	} {
		c := w.claims
		mutate(&c)

		if tok, err := w.signer.SignAccess(c); err == nil || tok.Value != "" {
			t.Errorf("%s: SignAccess = %+v, %v", name, tok, err)
		}
	}
}

func TestConstructorsRequireTheirInputs(t *testing.T) {
	w := newWorld(t)
	if _, err := jwt.NewSigner(nil, w.clock, issuer, audience, time.Minute); err == nil {
		t.Error("NewSigner accepted a nil ring")
	}

	for name, args := range map[string][3]any{
		"no issuer": {"", audience, time.Minute}, "no audience": {issuer, "", time.Minute}, "no ttl": {issuer, audience, time.Duration(0)},
	} {
		if _, err := jwt.NewSigner(w.ring, w.clock, args[0].(string), args[1].(string), args[2].(time.Duration)); err == nil {
			t.Errorf("NewSigner accepted %s", name)
		}
	}

	if _, err := jwt.NewSigner(w.ring, nil, issuer, audience, time.Minute); err == nil {
		t.Error("NewSigner accepted a nil clock")
	}

	keys := w.ring.PublicKeys()

	for name, build := range map[string]func() error{
		"no keys":         func() error { _, err := jwt.NewVerifier(nil, w.clock, issuer, audience, leeway); return err },
		"no clock":        func() error { _, err := jwt.NewVerifier(keys, nil, issuer, audience, leeway); return err },
		"no issuer":       func() error { _, err := jwt.NewVerifier(keys, w.clock, "", audience, leeway); return err },
		"no audience":     func() error { _, err := jwt.NewVerifier(keys, w.clock, issuer, "", leeway); return err },
		"negative leeway": func() error { _, err := jwt.NewVerifier(keys, w.clock, issuer, audience, -time.Second); return err },
		"empty kid": func() error {
			_, err := jwt.NewVerifier(map[string]*ecdsa.PublicKey{"": keys["sign-a"]}, w.clock, issuer, audience, leeway)
			return err
		},
	} {
		if build() == nil {
			t.Errorf("NewVerifier accepted %s", name)
		}
	}
}

func TestTimesAreUTCWhateverTheServerZone(t *testing.T) {
	previous := time.Local
	time.Local = time.FixedZone("EEST", 3*60*60)

	t.Cleanup(func() { time.Local = previous })

	w := newWorld(t)

	tok, err := w.signer.SignAccess(w.claims)
	if err != nil {
		t.Fatal(err)
	}

	got, err := w.verifier.VerifyAccess(tok.Value)
	if err != nil {
		t.Fatal(err)
	}

	for name, instant := range map[string]time.Time{
		"token ExpiresAt": tok.ExpiresAt, "claims ExpiresAt": got.ExpiresAt, "claims IssuedAt": got.IssuedAt, "claims AuthTime": got.AuthTime,
	} {
		if instant.Location() != time.UTC {
			t.Errorf("%s is in %v, want UTC", name, instant.Location())
		}
	}
}
