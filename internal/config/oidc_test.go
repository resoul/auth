package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.airlance.org/auth/internal/config"
)

// oidcEnv is an API configuration with the keys and the origin the provider needs.
func oidcEnv(t *testing.T) map[string]string {
	t.Helper()
	env := apiEnv(t, "127.0.0.1:8080")
	path := filepath.Join(t.TempDir(), "keyring.json")

	body := `{"format_version": 1,
		"otp_hmac": {"active_kid": "a", "keys": {"a": {"key_file": "f"}}},
		"jwt_signing": {"active_kid": "s", "keys": {"s": {"key_file": "s.pem"}}},
		"oidc_signing": {"active_kid": "o", "keys": {"o": {"key_file": "o.pem"}}}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	env[config.EnvKeyringFile] = path
	env[config.EnvOIDCIssuer] = "https://example.test"

	return env
}

func TestTheProviderIsOffByDefaultAndOnWithAnIssuer(t *testing.T) {
	cfg, err := config.Load(lookupFrom(apiEnv(t, "127.0.0.1:8080")))
	if err != nil || cfg.OIDC.Enabled() {
		t.Fatalf("OIDC = %+v, %v; want off", cfg.OIDC, err)
	}

	cfg, err = config.Load(lookupFrom(oidcEnv(t)))
	if err != nil || !cfg.OIDC.Enabled() || cfg.OIDC.Issuer != "https://example.test" {
		t.Fatalf("OIDC = %+v, %v", cfg.OIDC, err)
	}

	if cfg.Keyring.OIDCSigning == nil || cfg.Keyring.OIDCSigning.ActiveKID != "o" {
		t.Errorf("the oidc_signing purpose was not read: %+v", cfg.Keyring)
	}
}

func TestTheIssuerIsOneExactOrigin(t *testing.T) {
	for name, issuer := range map[string]string{
		"a trailing slash": "https://example.test/",
		"a path":           "https://example.test/auth",
		"a query":          "https://example.test?x=1",
		"a fragment":       "https://example.test#x",
		"credentials":      "https://u:p@example.test",
		"plain http":       "http://example.test",
		"no scheme":        "example.test",
		"upper case":       "https://Example.test",
		"another scheme":   "ftp://example.test",
		"empty host":       "https://",
	} {
		env := oidcEnv(t)

		env[config.EnvOIDCIssuer] = issuer
		if _, err := config.Load(lookupFrom(env)); err == nil || !strings.Contains(err.Error(), config.EnvOIDCIssuer) {
			t.Errorf("%s (%s): error = %v, want a refusal naming %s", name, issuer, err, config.EnvOIDCIssuer)
		}
	}
	// A development provider on localhost may use http; a passkey is never bound to an IP, so it is localhost, not 127.0.0.1.
	env := oidcEnv(t)
	env[config.EnvOIDCIssuer] = "http://localhost:8080"
	env[config.EnvWebAuthnRPID] = "localhost"

	env[config.EnvWebAuthnOrigins] = "http://localhost:8080"
	if _, err := config.Load(lookupFrom(env)); err != nil {
		t.Errorf("a localhost issuer: %v", err)
	}
}

func TestTheProviderNeedsItsKeysItsListenerAndItsOrigin(t *testing.T) {
	env := oidcEnv(t)
	delete(env, config.EnvHTTPAddr)

	if _, err := config.Load(lookupFrom(env)); err == nil || !strings.Contains(err.Error(), config.EnvHTTPAddr) {
		t.Errorf("without the API: %v", err)
	}

	// No oidc_signing purpose in the keyring.
	env = oidcEnv(t)
	plain := apiEnv(t, "127.0.0.1:8080")

	env[config.EnvKeyringFile] = plain[config.EnvKeyringFile]
	if _, err := config.Load(lookupFrom(env)); err == nil || !strings.Contains(err.Error(), "oidc_signing") {
		t.Errorf("without keys: %v", err)
	}

	// The sign-in page runs on the issuer's origin, which must be one passkeys are allowed on.
	env = oidcEnv(t)

	env[config.EnvOIDCIssuer] = "https://auth.example.test"
	if _, err := config.Load(lookupFrom(env)); err == nil || !strings.Contains(err.Error(), config.EnvWebAuthnOrigins) {
		t.Errorf("an issuer that is not a WebAuthn origin: %v", err)
	}
}

func TestTheKeyringReadsAndValidatesTheOIDCPurpose(t *testing.T) {
	ring, err := config.ParseKeyring([]byte(`{"format_version": 1, "oidc_signing": {"active_kid": "o", "keys": {"o": {"key_file": "/k/o.pem"}, "old": {"key_file": "/k/old.pem"}}}}`))
	if err != nil || ring.OIDCSigning == nil || ring.OIDCSigning.Keys["old"].KeyFile != "/k/old.pem" {
		t.Fatalf("ring = %+v, %v", ring, err)
	}

	for name, doc := range map[string]string{
		"the active kid is not in the keys": `{"format_version": 1, "oidc_signing": {"active_kid": "x", "keys": {"o": {"key_file": "f"}}}}`,
		"no keys":                           `{"format_version": 1, "oidc_signing": {"active_kid": "o", "keys": {}}}`,
		"no key file":                       `{"format_version": 1, "oidc_signing": {"active_kid": "o", "keys": {"o": {}}}}`,
		"an unknown field":                  `{"format_version": 1, "oidc_signing": {"active_kid": "o", "keys": {"o": {"key_file": "f"}}, "alg": "RS256"}}`,
	} {
		if _, err := config.ParseKeyring([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTheNetworksNoticesMayReachAreListed(t *testing.T) {
	env := oidcEnv(t)

	cfg, err := config.Load(lookupFrom(env))
	if err != nil || len(cfg.OIDC.BackchannelAllow) != 0 {
		t.Fatalf("by default nothing internal is allowed: %v, %v", cfg.OIDC.BackchannelAllow, err)
	}

	env[config.EnvOIDCBackchannelAllow] = "172.29.7.0/24, 10.1.2.3 ,fd00::/8"

	cfg, err = config.Load(lookupFrom(env))
	if err != nil || len(cfg.OIDC.BackchannelAllow) != 3 || cfg.OIDC.BackchannelAllow[1].String() != "10.1.2.3/32" {
		t.Fatalf("allowed = %v, %v", cfg.OIDC.BackchannelAllow, err)
	}

	for name, bad := range map[string]string{"everything": "0.0.0.0/0", "everything in IPv6": "::/0", "a name": "backend.internal", "an empty item": "10.0.0.0/8,", "a mask without a network": "/24"} {
		env[config.EnvOIDCBackchannelAllow] = bad
		if _, err := config.Load(lookupFrom(env)); err == nil || !strings.Contains(err.Error(), config.EnvOIDCBackchannelAllow) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
}
