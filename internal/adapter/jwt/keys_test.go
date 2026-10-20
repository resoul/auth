package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.airlance.org/auth/internal/adapter/jwt"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/testutil"
)

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func TestLoadRingAcceptsPrivateAndPublicKeys(t *testing.T) {
	a, b := testutil.NewSigningKeyPEM(t), testutil.NewSigningKeyPEM(t)

	ring, err := jwt.LoadRing("sign-b", map[string]string{
		"sign-a": testutil.WriteFile(t, "a.pub", a.Public), // old key: public only
		"sign-b": testutil.WriteFile(t, "b.pem", append(b.Private, '\n')),
	})
	if err != nil {
		t.Fatalf("LoadRing: %v", err)
	}

	if ring.ActiveKID() != "sign-b" || strings.Join(ring.KIDs(), ",") != "sign-a,sign-b" {
		t.Errorf("active=%q kids=%v", ring.ActiveKID(), ring.KIDs())
	}

	if len(ring.PublicKeys()) != 2 {
		t.Error("both keys must be available for verification")
	}
}

func TestLoadRingAcceptsAnOldPrivateKeyToo(t *testing.T) {
	a, b := testutil.NewSigningKeyPEM(t), testutil.NewSigningKeyPEM(t)
	if _, err := jwt.LoadRing("sign-b", map[string]string{
		"sign-a": testutil.WriteFile(t, "a.pem", a.Private), "sign-b": testutil.WriteFile(t, "b.pem", b.Private),
	}); err != nil {
		t.Errorf("a kept private key of an old kid must load: %v", err)
	}
}

func TestLoadRingRejectsBadKeys(t *testing.T) {
	good := testutil.NewSigningKeyPEM(t)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p384der, _ := x509.MarshalPKCS8PrivateKey(p384)
	p384pub, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsader, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sec1, _ := x509.MarshalECPrivateKey(p256)
	pkcs1 := x509.MarshalPKCS1PrivateKey(rsaKey)

	tests := map[string][]byte{
		"empty":               nil,
		"not PEM":             []byte("this is not a key"),
		"SEC1 EC PRIVATE KEY": pemBlock("EC PRIVATE KEY", sec1),
		"PKCS#1 RSA":          pemBlock("RSA PRIVATE KEY", pkcs1),
		"RSA in PKCS#8":       pemBlock("PRIVATE KEY", rsader),
		"P-384 private":       pemBlock("PRIVATE KEY", p384der),
		"P-384 public":        pemBlock("PUBLIC KEY", p384pub),
		"certificate":         pemBlock("CERTIFICATE", []byte("x")),
		"corrupt DER":         pemBlock("PRIVATE KEY", []byte("not der")),
		"two blocks":          append(append([]byte(nil), good.Private...), good.Public...),
		"trailing data":       append(append([]byte(nil), good.Private...), []byte("extra")...),
		"too large":           []byte(strings.Repeat("A", 9*1024)),
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			path := testutil.WriteFile(t, "key.pem", content)

			_, err := jwt.LoadRing("k", map[string]string{"k": path})
			if err == nil {
				t.Fatal("LoadRing succeeded")
			}

			if !strings.Contains(err.Error(), `"k"`) {
				t.Errorf("error %q does not name the kid", err)
			}
		})
	}

	dir := t.TempDir()
	if _, err := jwt.LoadRing("k", map[string]string{"k": dir}); err == nil {
		t.Error("a directory was accepted")
	}

	if _, err := jwt.LoadRing("k", map[string]string{"k": filepath.Join(dir, "absent")}); err == nil {
		t.Error("a missing file was accepted")
	}
}

func TestLoadRingChecksTheActiveKid(t *testing.T) {
	key := testutil.NewSigningKeyPEM(t)
	private := testutil.WriteFile(t, "a.pem", key.Private)
	public := testutil.WriteFile(t, "a.pub", key.Public)

	tests := []struct {
		name   string
		active string
		files  map[string]string
	}{
		{"no keys", "a", nil},
		{"active missing", "b", map[string]string{"a": private}},
		{"empty active", "", map[string]string{"a": private}},
		{"active is public only", "a", map[string]string{"a": public}},
		{"empty kid", "", map[string]string{"": private}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := jwt.LoadRing(tt.active, tt.files); err == nil {
				t.Error("LoadRing succeeded")
			}
		})
	}
}

func TestLoadRingErrorsAndFormattingDoNotLeakKeyMaterial(t *testing.T) {
	key := testutil.NewSigningKeyPEM(t)
	body := strings.TrimSpace(strings.NewReplacer("-----BEGIN PRIVATE KEY-----", "", "-----END PRIVATE KEY-----", "", "\n", "").Replace(string(key.Private)))

	// A key that parses as PEM but not as a key: the error must not echo it.
	corrupt := pemBlock("PRIVATE KEY", []byte(body))

	_, err := jwt.LoadRing("k", map[string]string{"k": testutil.WriteFile(t, "k.pem", corrupt)})
	if err == nil || strings.Contains(err.Error(), body[:20]) {
		t.Errorf("error %v echoes the key body", err)
	}

	ring, err := jwt.LoadRing("k", map[string]string{"k": testutil.WriteFile(t, "k.pem", key.Private)})
	if err != nil {
		t.Fatal(err)
	}

	for _, out := range []string{fmt.Sprintf("%v", ring), fmt.Sprintf("%+v", ring), fmt.Sprintf("%#v", ring)} {
		if strings.Contains(out, body[:20]) || strings.Contains(out, "PRIVATE") {
			t.Errorf("formatted ring %q leaks key material", out)
		}
	}
}

func TestJWKSPublishesPublicKeysOnly(t *testing.T) {
	a, b := testutil.NewSigningKeyPEM(t), testutil.NewSigningKeyPEM(t)

	ring, err := jwt.LoadRing("sign-b", map[string]string{
		"sign-a": testutil.WriteFile(t, "a.pem", a.Private), // even a kept private key is never published
		"sign-b": testutil.WriteFile(t, "b.pem", b.Private),
	})
	if err != nil {
		t.Fatal(err)
	}

	data, err := ring.JWKS()
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}

	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}

	if len(doc.Keys) != 2 || doc.Keys[0]["kid"] != "sign-a" || doc.Keys[1]["kid"] != "sign-b" {
		t.Fatalf("keys = %v, want sign-a then sign-b", doc.Keys)
	}

	for _, k := range doc.Keys {
		if k["kty"] != "EC" || k["crv"] != "P-256" || k["alg"] != "ES256" || k["use"] != "sig" || k["x"] == nil || k["y"] == nil {
			t.Errorf("key = %v", k)
		}

		for _, secret := range []string{"d", "p", "q", "k"} {
			if _, ok := k[secret]; ok {
				t.Errorf("JWKS contains private parameter %q: %v", secret, k)
			}
		}
	}
}

func TestParseJWKSRoundTripsAndRejectsUnsafeSets(t *testing.T) {
	key := testutil.NewSigningKeyPEM(t)
	ring, _ := jwt.LoadRing("a", map[string]string{"a": testutil.WriteFile(t, "a.pem", key.Private)})
	data, _ := ring.JWKS()

	keys, err := jwt.ParseJWKS(data)
	if err != nil || len(keys) != 1 || keys["a"] == nil || !keys["a"].Equal(ring.PublicKeys()["a"]) {
		t.Fatalf("ParseJWKS = %v, %v", keys, err)
	}

	jwk := func(extra string) string {
		return strings.Replace(string(data), `"kid":"a"`, `"kid":"a"`+extra, 1)
	}

	for name, in := range map[string]string{
		"empty":            "",
		"not JSON":         "keys",
		"no keys":          `{"keys":[]}`,
		"no kid":           strings.Replace(string(data), `"kid":"a"`, `"kid":""`, 1),
		"wrong use":        strings.Replace(string(data), `"use":"sig"`, `"use":"enc"`, 1),
		"wrong alg":        strings.Replace(string(data), `"alg":"ES256"`, `"alg":"RS256"`, 1),
		"duplicate kid":    `{"keys":[` + keyOf(t, data) + `,` + keyOf(t, data) + `]}`,
		"private material": jwk(`,"d":"` + dOf(t, key) + `"`),
	} {
		if _, err := jwt.ParseJWKS([]byte(in)); err == nil {
			t.Errorf("%s: ParseJWKS accepted the set", name)
		}
	}
}

func keyOf(t *testing.T, jwks []byte) string {
	t.Helper()

	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &doc); err != nil {
		t.Fatal(err)
	}

	return string(doc.Keys[0])
}

// dOf returns the private scalar of the PEM key as base64url, to prove ParseJWKS refuses it.
func dOf(t *testing.T, key testutil.SigningKeyPEM) string {
	t.Helper()

	block, _ := pem.Decode(key.Private)

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	scalar, err := parsed.(*ecdsa.PrivateKey).Bytes()
	if err != nil {
		t.Fatal(err)
	}

	return base64.RawURLEncoding.EncodeToString(scalar)
}

// ---- restart and rotation ----

func ringFrom(t *testing.T, active string, files map[string][]byte) *jwt.Ring {
	t.Helper()

	paths := map[string]string{}
	for kid, content := range files {
		paths[kid] = testutil.WriteFile(t, kid+".pem", content)
	}

	ring, err := jwt.LoadRing(active, paths)
	if err != nil {
		t.Fatalf("LoadRing: %v", err)
	}

	return ring
}

func signerAndVerifier(t *testing.T, ring *jwt.Ring, clock port.Clock) (*jwt.Signer, *jwt.Verifier) {
	t.Helper()

	signer, err := jwt.NewSigner(ring, clock, issuer, audience, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := jwt.NewVerifier(ring.PublicKeys(), clock, issuer, audience, leeway)
	if err != nil {
		t.Fatal(err)
	}

	return signer, verifier
}

func TestRestartPublishesTheSameRingAndKeepsTokensValid(t *testing.T) {
	w := newWorld(t)
	token := w.token()

	firstJWKS, err := w.ring.JWKS()
	if err != nil {
		t.Fatal(err)
	}

	// "Restart": load the same files again into a fresh process state.
	restarted := ringFrom(t, "sign-a", map[string][]byte{"sign-a": w.pem.Private})

	secondJWKS, err := restarted.JWKS()
	if err != nil {
		t.Fatal(err)
	}

	if string(firstJWKS) != string(secondJWKS) {
		t.Errorf("a restart changed the published keys:\n%s\n%s", firstJWKS, secondJWKS)
	}

	_, verifier := signerAndVerifier(t, restarted, w.clock)
	if _, err := verifier.VerifyAccess(token); err != nil {
		t.Errorf("a token issued before the restart no longer verifies: %v", err)
	}
}

func TestRotationOverlapKeepsOldAndNewTokensValid(t *testing.T) {
	clock := testutil.NewFakeClock(t0)
	keyA, keyB := testutil.NewSigningKeyPEM(t), testutil.NewSigningKeyPEM(t)
	f := testutil.NewFactory(t, t0)
	user := f.User(testutil.UserSpec{})
	claims := port.AccessClaims{UserID: user.ID(), SessionID: f.Session(testutil.SessionSpec{User: user}).ID(), AuthTime: t0, AMR: []string{"otp"}}
	issue := func(s *jwt.Signer) string {
		t.Helper()

		tok, err := s.SignAccess(claims)
		if err != nil {
			t.Fatal(err)
		}

		return tok.Value
	}

	// Step 0: only A exists and signs.
	ring0 := ringFrom(t, "a", map[string][]byte{"a": keyA.Private})
	signer0, _ := signerAndVerifier(t, ring0, clock)
	tokenA := issue(signer0)

	// Step 1: B's public key is published while A still signs. A service refreshes its
	// JWKS cache now and learns both keys.
	ring1 := ringFrom(t, "a", map[string][]byte{"a": keyA.Private, "b": keyB.Public})

	jwks1, err := ring1.JWKS()
	if err != nil {
		t.Fatal(err)
	}

	cached, err := jwt.ParseJWKS(jwks1)
	if err != nil {
		t.Fatal(err)
	}

	serviceVerifier, err := jwt.NewVerifier(cached, clock, issuer, audience, leeway)
	if err != nil {
		t.Fatal(err)
	}

	// Step 2: the active key switches to B; A stays as a public key.
	ring2 := ringFrom(t, "b", map[string][]byte{"a": keyA.Public, "b": keyB.Private})
	signer2, verifier2 := signerAndVerifier(t, ring2, clock)
	tokenB := issue(signer2)

	if got, err := verifier2.VerifyAccess(tokenA); err != nil || got.UserID != claims.UserID {
		t.Errorf("a token signed by the old key must verify during the overlap: %v", err)
	}

	if _, err := verifier2.VerifyAccess(tokenB); err != nil {
		t.Errorf("a token of the new key must verify: %v", err)
	}
	// The service never fetched anything after step 1, yet it accepts the new key:
	// that is why the public key goes out before the switch.
	if _, err := serviceVerifier.VerifyAccess(tokenB); err != nil {
		t.Errorf("a service with the step-1 cache rejects the new key: %v", err)
	}

	if _, err := serviceVerifier.VerifyAccess(tokenA); err != nil {
		t.Errorf("a service with the step-1 cache rejects the old key: %v", err)
	}

	// Step 3: after expiry plus skew the old public key is removed.
	ring3 := ringFrom(t, "b", map[string][]byte{"b": keyB.Private})

	_, verifier3 := signerAndVerifier(t, ring3, clock)
	if _, err := verifier3.VerifyAccess(tokenA); !isInvalid(err) {
		t.Errorf("a token of a removed key still verifies: %v", err)
	}

	if _, err := verifier3.VerifyAccess(tokenB); err != nil {
		t.Errorf("the new key must keep working: %v", err)
	}
}

func TestActivePrivateKeyNeverLeavesTheProcessViaJWKS(t *testing.T) {
	key := testutil.NewSigningKeyPEM(t)
	ring := ringFrom(t, "a", map[string][]byte{"a": key.Private})
	data, _ := ring.JWKS()

	block, _ := pem.Decode(key.Private)
	if strings.Contains(string(data), dOf(t, key)) || strings.Contains(string(data), string(block.Bytes)) {
		t.Error("the JWKS contains private key material")
	}
}
