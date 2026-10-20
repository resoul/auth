package config_test

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.airlance.org/auth/internal/config"
)

func lookupFrom(env map[string]string) config.LookupFunc {
	return func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := config.Load(lookupFrom(nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Log.Level != slog.LevelInfo || cfg.Log.Format != config.LogFormatJSON {
		t.Errorf("log = %+v, want info/json", cfg.Log)
	}

	if cfg.ShutdownTimeout != 15*time.Second {
		t.Errorf("ShutdownTimeout = %v, want 15s", cfg.ShutdownTimeout)
	}

	if cfg.Keyring != nil {
		t.Errorf("Keyring = %+v, want nil", cfg.Keyring)
	}
}

func TestLoadEmptyValueTakesDefault(t *testing.T) {
	cfg, err := config.Load(lookupFrom(map[string]string{config.EnvLogLevel: "", config.EnvShutdownTimeout: ""}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Log.Level != slog.LevelInfo || cfg.ShutdownTimeout != 15*time.Second {
		t.Errorf("got %+v, want defaults", cfg)
	}
}

func TestLoadValues(t *testing.T) {
	cfg, err := config.Load(lookupFrom(map[string]string{
		config.EnvLogLevel:        "debug",
		config.EnvLogFormat:       "text",
		config.EnvShutdownTimeout: "2s",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Log.Level != slog.LevelDebug || cfg.Log.Format != config.LogFormatText || cfg.ShutdownTimeout != 2*time.Second {
		t.Errorf("got %+v", cfg)
	}
}

func TestLoadRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"level name", map[string]string{config.EnvLogLevel: "verbose"}, config.EnvLogLevel},
		{"level offset", map[string]string{config.EnvLogLevel: "info+2"}, config.EnvLogLevel},
		{"format", map[string]string{config.EnvLogFormat: "xml"}, config.EnvLogFormat},
		{"timeout syntax", map[string]string{config.EnvShutdownTimeout: "soon"}, config.EnvShutdownTimeout},
		{"timeout zero", map[string]string{config.EnvShutdownTimeout: "0s"}, config.EnvShutdownTimeout},
		{"timeout negative", map[string]string{config.EnvShutdownTimeout: "-1s"}, config.EnvShutdownTimeout},
		{"keyring missing file", map[string]string{config.EnvKeyringFile: filepath.Join(t.TempDir(), "absent.json")}, config.EnvKeyringFile},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := config.Load(lookupFrom(tt.env))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load error = %v, want mention of %s", err, tt.want)
			}
		})
	}
}

func TestLoadReportsAllInvalidValues(t *testing.T) {
	_, err := config.Load(lookupFrom(map[string]string{
		config.EnvLogLevel:  "loud",
		config.EnvLogFormat: "xml",
	}))
	if err == nil || !strings.Contains(err.Error(), config.EnvLogLevel) || !strings.Contains(err.Error(), config.EnvLogFormat) {
		t.Fatalf("Load error = %v, want both variables reported", err)
	}
}

func TestLoadKeyringFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.json")
	if err := os.WriteFile(path, []byte(validKeyring), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load(lookupFrom(map[string]string{
		config.EnvKeyringFile: path, config.EnvJWTIssuer: "https://auth.example.test", config.EnvJWTAudience: "example",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Keyring == nil || cfg.Keyring.OTPHMAC.ActiveKID != "otp-a" {
		t.Errorf("Keyring = %+v", cfg.Keyring)
	}
}

func TestLoadDatabaseURL(t *testing.T) {
	const dsn = "postgres://airlance_auth:hunter2@127.0.0.1:5432/airlance_auth?sslmode=disable"

	cfg, err := config.Load(lookupFrom(map[string]string{config.EnvDatabaseURL: dsn}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !cfg.Database.URL.IsSet() || cfg.Database.URL.Reveal() != dsn {
		t.Errorf("URL not loaded: set=%v", cfg.Database.URL.IsSet())
	}

	for _, scheme := range []string{"postgresql"} {
		if _, err := config.Load(lookupFrom(map[string]string{config.EnvDatabaseURL: scheme + "://u:p@h/db"})); err != nil {
			t.Errorf("scheme %s rejected: %v", scheme, err)
		}
	}
}

func TestLoadRejectsBadDatabaseURLWithoutEchoingIt(t *testing.T) {
	for _, in := range []string{"mysql://u:hunter2@h/db", "postgres://", "postgres:///db", "hunter2", "://u:hunter2@h", "postgres://u:hunter2@h:notaport/db"} {
		_, err := config.Load(lookupFrom(map[string]string{config.EnvDatabaseURL: in}))
		if err == nil || !strings.Contains(err.Error(), config.EnvDatabaseURL) {
			t.Errorf("Load(%q) error = %v, want a complaint about the variable", in, err)
			continue
		}

		if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("error %q echoes the password", err)
		}
	}
}

func TestDatabaseURLIsUnsetByDefault(t *testing.T) {
	cfg, err := config.Load(lookupFrom(nil))
	if err != nil || cfg.Database.URL.IsSet() {
		t.Errorf("default Database = %+v, %v", cfg.Database, err)
	}
}

func TestLoadJWTSettings(t *testing.T) {
	cfg, err := config.Load(lookupFrom(map[string]string{
		config.EnvJWTIssuer: " https://auth.example.test ", config.EnvJWTAudience: "example", config.EnvAccessTTL: "10m",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.JWT.Issuer != "https://auth.example.test" || cfg.JWT.Audience != "example" || cfg.JWT.AccessTTL != 10*time.Minute {
		t.Errorf("JWT = %+v", cfg.JWT)
	}

	defaults, err := config.Load(lookupFrom(nil))
	if err != nil || defaults.JWT.AccessTTL != 5*time.Minute {
		t.Errorf("default access TTL = %v, %v; want 5m", defaults.JWT.AccessTTL, err)
	}
}

func TestLoadRejectsBadAccessTTL(t *testing.T) {
	for _, in := range []string{"soon", "0s", "-1m", "61m", "24h"} {
		_, err := config.Load(lookupFrom(map[string]string{config.EnvAccessTTL: in}))
		if err == nil || !strings.Contains(err.Error(), config.EnvAccessTTL) {
			t.Errorf("Load(%q) error = %v", in, err)
		}
	}
}

func TestJWTSigningRequiresIssuerAndAudience(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.json")
	if err := os.WriteFile(path, []byte(validKeyring), 0o600); err != nil {
		t.Fatal(err)
	}

	for name, env := range map[string]map[string]string{
		"neither":      {},
		"no audience":  {config.EnvJWTIssuer: "https://auth.example.test"},
		"no issuer":    {config.EnvJWTAudience: "example"},
		"blank values": {config.EnvJWTIssuer: "  ", config.EnvJWTAudience: "  "},
	} {
		env[config.EnvKeyringFile] = path

		_, err := config.Load(lookupFrom(env))
		if err == nil || !strings.Contains(err.Error(), "jwt_signing") {
			t.Errorf("%s: error = %v, want a request for issuer and audience", name, err)
		}
	}

	// A keyring without jwt_signing does not need them.
	otpOnly := filepath.Join(t.TempDir(), "otp.json")

	body := `{"format_version": 1, "otp_hmac": {"active_kid": "a", "keys": {"a": {"key_file": "f"}}}}`
	if err := os.WriteFile(otpOnly, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := config.Load(lookupFrom(map[string]string{config.EnvKeyringFile: otpOnly})); err != nil {
		t.Errorf("an OTP-only keyring needs no JWT settings: %v", err)
	}
}

func smtpEnv(extra map[string]string) map[string]string {
	env := map[string]string{
		config.EnvSMTPAddr: "smtp.example.test:587", config.EnvMailFrom: "no-reply@example.test",
	}
	for k, v := range extra {
		env[k] = v
	}

	return env
}

func TestSMTPDefaultsToMandatoryTLS(t *testing.T) {
	cfg, err := config.Load(lookupFrom(nil))
	if err != nil || cfg.SMTP.Enabled() || cfg.SMTP.TLS != config.SMTPTLSStartTLS {
		t.Errorf("default SMTP = %+v, %v", cfg.SMTP, err)
	}
}

func TestSMTPNeedsTheDatabaseAndTheOTPKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keyring.json")
	if err := os.WriteFile(path, []byte(`{"format_version": 1, "otp_hmac": {"active_kid": "a", "keys": {"a": {"key_file": "f"}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	const dsn = "postgres://u:p@127.0.0.1:5432/db"

	cfg, err := config.Load(lookupFrom(smtpEnv(map[string]string{config.EnvDatabaseURL: dsn, config.EnvKeyringFile: path, config.EnvSMTPTLS: "tls", config.EnvMailFromName: " Example Auth "})))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	s := cfg.SMTP
	if !s.Enabled() || s.Host != "smtp.example.test" || s.Port != 587 || s.TLS != "tls" || s.From != "no-reply@example.test" || s.FromName != "Example Auth" {
		t.Errorf("SMTP = %+v", s)
	}

	for name, env := range map[string]map[string]string{
		"no database": smtpEnv(map[string]string{config.EnvKeyringFile: path}),
		"no keyring":  smtpEnv(map[string]string{config.EnvDatabaseURL: dsn}),
	} {
		if _, err := config.Load(lookupFrom(env)); err == nil {
			t.Errorf("%s: Load accepted the configuration", name)
		}
	}
}

func TestSMTPSettingsAreValidated(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"no port":                          smtpEnv(map[string]string{config.EnvSMTPAddr: "smtp.example.test"}),
		"port out of range":                smtpEnv(map[string]string{config.EnvSMTPAddr: "smtp.example.test:70000"}),
		"port not a number":                smtpEnv(map[string]string{config.EnvSMTPAddr: "smtp.example.test:smtp"}),
		"no host":                          smtpEnv(map[string]string{config.EnvSMTPAddr: ":587"}),
		"unknown tls mode":                 smtpEnv(map[string]string{config.EnvSMTPTLS: "ssl"}),
		"username without password":        smtpEnv(map[string]string{config.EnvSMTPUsername: "u"}),
		"password without username":        smtpEnv(map[string]string{config.EnvSMTPPassword: "p"}),
		"credentials without tls":          smtpEnv(map[string]string{config.EnvSMTPUsername: "u", config.EnvSMTPPassword: "p", config.EnvSMTPTLS: "none"}),
		"no sender":                        {config.EnvSMTPAddr: "smtp.example.test:587"},
		"sender with a name":               smtpEnv(map[string]string{config.EnvMailFrom: "Auth <no-reply@example.test>"}),
		"sender not an address":            smtpEnv(map[string]string{config.EnvMailFrom: "no-reply"}),
		"mail settings without an address": {config.EnvMailFrom: "no-reply@example.test"},
		"credentials without an address":   {config.EnvSMTPUsername: "u"},
	} {
		if _, err := config.Load(lookupFrom(env)); err == nil {
			t.Errorf("%s: Load accepted the configuration", name)
		}
	}
}

func TestSMTPPasswordIsNeverPrintedOrEchoed(t *testing.T) {
	const password = "hunter2-smtp"

	env := smtpEnv(map[string]string{config.EnvSMTPUsername: "u", config.EnvSMTPPassword: password, config.EnvSMTPTLS: "starttls"})
	env[config.EnvDatabaseURL] = "postgres://u:p@127.0.0.1:5432/db"
	// Not valid as a whole (no keyring): the error must still not echo the password.
	_, err := config.Load(lookupFrom(env))
	if err == nil || strings.Contains(err.Error(), password) {
		t.Errorf("error = %v", err)
	}

	cfg := config.Config{SMTP: config.SMTPConfig{Password: config.NewSecret(password)}}
	if strings.Contains(fmt.Sprintf("%v %+v %#v", cfg, cfg, cfg), password) {
		t.Error("the password is printed")
	}
}

// apiEnv is a complete API configuration: database, both key purposes and token claims.
func apiEnv(t *testing.T, addr string) map[string]string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keyring.json")

	body := `{"format_version": 1,
		"otp_hmac": {"active_kid": "a", "keys": {"a": {"key_file": "f"}}},
		"jwt_signing": {"active_kid": "s", "keys": {"s": {"key_file": "s.pem"}}}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	return map[string]string{
		config.EnvHTTPAddr: addr, config.EnvDatabaseURL: "postgres://u:p@127.0.0.1:5432/db", config.EnvKeyringFile: path,
		config.EnvJWTIssuer: "https://auth.example.test", config.EnvJWTAudience: "example",
		config.EnvWebAuthnRPID: "example.test", config.EnvWebAuthnOrigins: "https://example.test",
	}
}

func TestHTTPIsOffByDefault(t *testing.T) {
	cfg, err := config.Load(lookupFrom(nil))
	if err != nil || cfg.HTTP.Enabled() {
		t.Errorf("default HTTP = %+v, %v", cfg.HTTP, err)
	}
}

func TestHTTPListensOnAnyIPButBeyondTheLoopbackNeedsATrustedProxy(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:8080", "127.0.0.2:8080", "[::1]:8080"} {
		cfg, err := config.Load(lookupFrom(apiEnv(t, addr)))
		if err != nil || cfg.HTTP.Addr != addr {
			t.Errorf("%s: HTTP = %+v, %v", addr, cfg.HTTP, err)
		}
	}

	for _, addr := range []string{"0.0.0.0:8080", "[::]:8080", "192.168.1.10:8080", "[2001:db8::1]:8080"} {
		_, err := config.Load(lookupFrom(apiEnv(t, addr)))
		if err == nil || !strings.Contains(err.Error(), config.EnvTrustedProxies) {
			t.Errorf("%s without a trusted proxy: error = %v, want a request for %s", addr, err, config.EnvTrustedProxies)
		}

		env := apiEnv(t, addr)
		env[config.EnvTrustedProxies] = "10.0.0.0/8"

		cfg, err := config.Load(lookupFrom(env))
		if err != nil || cfg.HTTP.Addr != addr {
			t.Errorf("%s behind a trusted proxy: HTTP = %+v, %v", addr, cfg.HTTP, err)
		}
	}

	for name, addr := range map[string]string{
		"empty host":        ":8080",
		"host name":         "localhost:8080",
		"no port":           "127.0.0.1",
		"port zero":         "127.0.0.1:0",
		"port out of range": "127.0.0.1:70000",
		"zone":              "[::1%lo0]:8080",
	} {
		_, err := config.Load(lookupFrom(apiEnv(t, addr)))
		if err == nil || !strings.Contains(err.Error(), config.EnvHTTPAddr) {
			t.Errorf("%s (%s): error = %v, want a refusal naming %s", name, addr, err, config.EnvHTTPAddr)
		}
	}
}

func TestHTTPNeedsTheDatabaseAndBothKeyPurposes(t *testing.T) {
	otpOnly := filepath.Join(t.TempDir(), "otp.json")
	if err := os.WriteFile(otpOnly, []byte(`{"format_version": 1, "otp_hmac": {"active_kid": "a", "keys": {"a": {"key_file": "f"}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	for name, mutate := range map[string]func(map[string]string){
		"no database":    func(env map[string]string) { delete(env, config.EnvDatabaseURL) },
		"no keyring":     func(env map[string]string) { delete(env, config.EnvKeyringFile) },
		"no jwt_signing": func(env map[string]string) { env[config.EnvKeyringFile] = otpOnly },
	} {
		env := apiEnv(t, "127.0.0.1:8080")
		mutate(env)

		if _, err := config.Load(lookupFrom(env)); err == nil {
			t.Errorf("%s: Load accepted the configuration", name)
		}
	}
}

func TestTrustedProxiesAreParsedAndMasked(t *testing.T) {
	env := apiEnv(t, "127.0.0.1:8080")
	env[config.EnvTrustedProxies] = " 10.1.2.3/8, 192.0.2.7 ,fd00::/8"

	cfg, err := config.Load(lookupFrom(env))
	if err != nil {
		t.Fatal(err)
	}

	var got []string
	for _, p := range cfg.HTTP.TrustedProxies {
		got = append(got, p.String())
	}

	if want := "10.0.0.0/8 192.0.2.7/32 fd00::/8"; strings.Join(got, " ") != want {
		t.Errorf("trusted proxies = %v, want %s", got, want)
	}

	if cfg, err := config.Load(lookupFrom(apiEnv(t, "127.0.0.1:8080"))); err != nil || len(cfg.HTTP.TrustedProxies) != 0 {
		t.Errorf("default trusted proxies = %v, %v: no proxy is trusted unless configured", cfg.HTTP.TrustedProxies, err)
	}
}

func TestTrustedProxiesRefuseNetworksOfEveryAddress(t *testing.T) {
	for name, value := range map[string]string{
		"everything v4":   "0.0.0.0/0",
		"everything v6":   "::/0",
		"one of the list": "10.0.0.0/8, 0.0.0.0/0",
		"garbage":         "proxy.example.test",
		"empty item":      "10.0.0.0/8,,192.0.2.1",
		"bad prefix":      "10.0.0.0/33",
	} {
		env := apiEnv(t, "127.0.0.1:8080")
		env[config.EnvTrustedProxies] = value

		_, err := config.Load(lookupFrom(env))
		if err == nil || !strings.Contains(err.Error(), config.EnvTrustedProxies) {
			t.Errorf("%s (%q): error = %v, want a refusal naming %s", name, value, err, config.EnvTrustedProxies)
		}
	}
}

func TestBrowserOriginsAreExactAndNormalized(t *testing.T) {
	env := apiEnv(t, "127.0.0.1:8080")
	env[config.EnvBrowserOrigins] = " https://App.Example.test , https://other.example.test:8443,http://localhost:3000, http://127.0.0.1:5173"

	cfg, err := config.Load(lookupFrom(env))
	if err != nil {
		t.Fatal(err)
	}

	want := "https://app.example.test https://other.example.test:8443 http://localhost:3000 http://127.0.0.1:5173"
	if got := strings.Join(cfg.HTTP.BrowserOrigins, " "); got != want {
		t.Errorf("origins = %s, want %s", got, want)
	}

	if cfg, err := config.Load(lookupFrom(apiEnv(t, "127.0.0.1:8080"))); err != nil || len(cfg.HTTP.BrowserOrigins) != 0 || cfg.HTTP.CookieSameSite != "" {
		t.Errorf("defaults = %+v, %v: no foreign origin is trusted unless configured", cfg.HTTP, err)
	}
}

func TestBrowserOriginsRefuseWildcardsPathsAndRemotePlainHTTP(t *testing.T) {
	for name, value := range map[string]string{
		"wildcard":               "*",
		"wildcard host":          "https://*.example.test",
		"path":                   "https://app.example.test/login",
		"trailing slash":         "https://app.example.test/",
		"query":                  "https://app.example.test?x=1",
		"credentials":            "https://user:pw@app.example.test",
		"no scheme":              "app.example.test",
		"other scheme":           "ftp://app.example.test",
		"remote plain http":      "http://app.example.test",
		"empty item":             "https://a.example.test,,https://b.example.test",
		"one bad among good":     "https://a.example.test, http://b.example.test",
		"opaque":                 "mailto:a@example.test",
		"http on a lookalike":    "http://localhost.example.test",
		"http on a private host": "http://192.168.1.10",
	} {
		env := apiEnv(t, "127.0.0.1:8080")
		env[config.EnvBrowserOrigins] = value

		_, err := config.Load(lookupFrom(env))
		if err == nil || !strings.Contains(err.Error(), config.EnvBrowserOrigins) {
			t.Errorf("%s (%q): error = %v, want a refusal naming %s", name, value, err, config.EnvBrowserOrigins)
		}
	}
}

func TestCookieSameSite(t *testing.T) {
	for value, want := range map[string]string{"strict": "strict", "LAX": "lax", "None": "none"} {
		env := apiEnv(t, "127.0.0.1:8080")
		env[config.EnvCookieSameSite] = value
		env[config.EnvBrowserOrigins] = "https://app.example.test"

		cfg, err := config.Load(lookupFrom(env))
		if err != nil || cfg.HTTP.CookieSameSite != want {
			t.Errorf("%s: SameSite = %q, %v, want %q", value, cfg.HTTP.CookieSameSite, err, want)
		}
	}

	env := apiEnv(t, "127.0.0.1:8080")

	env[config.EnvCookieSameSite] = "sometimes"
	if _, err := config.Load(lookupFrom(env)); err == nil || !strings.Contains(err.Error(), config.EnvCookieSameSite) {
		t.Errorf("an unknown value: %v", err)
	}

	env[config.EnvCookieSameSite] = "none"
	if _, err := config.Load(lookupFrom(env)); err == nil || !strings.Contains(err.Error(), config.EnvBrowserOrigins) {
		t.Errorf("SameSite=None without an origin: %v", err)
	}
}

func TestDatabaseMaxConns(t *testing.T) {
	cfg, err := config.Load(lookupFrom(map[string]string{config.EnvDatabaseMaxConns: "12"}))
	if err != nil || cfg.Database.MaxConns != 12 {
		t.Errorf("MaxConns = %d, %v", cfg.Database.MaxConns, err)
	}

	if cfg, err := config.Load(lookupFrom(nil)); err != nil || cfg.Database.MaxConns != 0 {
		t.Errorf("default MaxConns = %d, %v: unset keeps the driver default", cfg.Database.MaxConns, err)
	}

	for _, bad := range []string{"0", "-1", "101", "many", "1.5"} {
		_, err := config.Load(lookupFrom(map[string]string{config.EnvDatabaseMaxConns: bad}))
		if err == nil || !strings.Contains(err.Error(), config.EnvDatabaseMaxConns) {
			t.Errorf("%q: error = %v", bad, err)
		}
	}
}

func TestMetricsListenerIsOffByDefault(t *testing.T) {
	cfg, err := config.Load(lookupFrom(apiEnv(t, "127.0.0.1:8080")))
	if err != nil || cfg.Metrics.Enabled() {
		t.Errorf("default Metrics = %+v, %v", cfg.Metrics, err)
	}
}

func TestMetricsMayListenOnAnyIPWithoutAProxy(t *testing.T) {
	// The metrics listener serves no client, so no proxy is needed; it is for the compose network or the cluster.
	for _, addr := range []string{"127.0.0.1:9090", "[::1]:9090", "0.0.0.0:9090", "[::]:9090", "10.0.0.5:9090"} {
		env := apiEnv(t, "127.0.0.1:8080")
		env[config.EnvMetricsAddr] = addr

		cfg, err := config.Load(lookupFrom(env))
		if err != nil || cfg.Metrics.Addr != addr {
			t.Errorf("%s: Metrics = %+v, %v", addr, cfg.Metrics, err)
		}
	}

	for name, addr := range map[string]string{
		"empty host": ":9090",
		"host name":  "localhost:9090",
		"no port":    "127.0.0.1",
	} {
		env := apiEnv(t, "127.0.0.1:8080")
		env[config.EnvMetricsAddr] = addr

		_, err := config.Load(lookupFrom(env))
		if err == nil || !strings.Contains(err.Error(), config.EnvMetricsAddr) {
			t.Errorf("%s (%s): error = %v, want a refusal naming %s", name, addr, err, config.EnvMetricsAddr)
		}
	}
}

func TestMetricsListenerNeedsSomethingToMeasureAndItsOwnPort(t *testing.T) {
	env := apiEnv(t, "127.0.0.1:8080")

	env[config.EnvMetricsAddr] = "127.0.0.1:8080"
	if _, err := config.Load(lookupFrom(env)); err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Errorf("same address as the API: error = %v", err)
	}

	alone := map[string]string{config.EnvMetricsAddr: "127.0.0.1:9090"}
	if _, err := config.Load(lookupFrom(alone)); err == nil || !strings.Contains(err.Error(), config.EnvMetricsAddr) {
		t.Errorf("metrics without API or SMTP: error = %v", err)
	}
}

func TestWebAuthnIsRequiredWithTheAPI(t *testing.T) {
	cfg, err := config.Load(lookupFrom(apiEnv(t, "127.0.0.1:8080")))
	if err != nil || cfg.WebAuthn.RPID != "example.test" || len(cfg.WebAuthn.Origins) != 1 || cfg.WebAuthn.Origins[0] != "https://example.test" {
		t.Fatalf("WebAuthn = %+v, %v", cfg.WebAuthn, err)
	}

	for _, key := range []string{config.EnvWebAuthnRPID, config.EnvWebAuthnOrigins} {
		env := apiEnv(t, "127.0.0.1:8080")
		delete(env, key)

		if _, err := config.Load(lookupFrom(env)); err == nil || !strings.Contains(err.Error(), key) {
			t.Errorf("without %s: error = %v, want a refusal naming it", key, err)
		}
	}
}

func TestWebAuthnRelyingPartyIsChecked(t *testing.T) {
	load := func(rpID, origins string) error {
		env := apiEnv(t, "127.0.0.1:8080")
		env[config.EnvWebAuthnRPID], env[config.EnvWebAuthnOrigins] = rpID, origins
		_, err := config.Load(lookupFrom(env))

		return err
	}
	for name, tc := range map[string]struct{ rpID, origins string }{
		"a relying party and its subdomain":   {"example.test", "https://example.test,https://app.example.test"},
		"localhost for development":           {"localhost", "http://localhost:5173"},
		"an android app next to the web site": {"example.test", "https://example.test,android:apk-key-hash:abc123_-xyz"},
		"a case-insensitive relying party":    {"Example.Test", "https://example.test"},
	} {
		if err := load(tc.rpID, tc.origins); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	for name, tc := range map[string]struct{ rpID, origins, want string }{
		"a scheme in the relying party":    {"https://example.test", "https://example.test", config.EnvWebAuthnRPID},
		"a port in the relying party":      {"example.test:8080", "https://example.test", config.EnvWebAuthnRPID},
		"an IP as the relying party":       {"127.0.0.1", "http://127.0.0.1", config.EnvWebAuthnRPID},
		"an underscore":                    {"my_site.test", "https://my_site.test", config.EnvWebAuthnRPID},
		"an origin of another domain":      {"example.test", "https://evil.test", config.EnvWebAuthnOrigins},
		"a lookalike domain":               {"example.test", "https://badexample.test", config.EnvWebAuthnOrigins},
		"a wildcard origin":                {"example.test", "https://*.example.test", config.EnvWebAuthnOrigins},
		"a plain http origin off the host": {"example.test", "http://example.test", config.EnvWebAuthnOrigins},
		"an origin with a path":            {"example.test", "https://example.test/login", config.EnvWebAuthnOrigins},
		"an android origin without a hash": {"example.test", "android:apk-key-hash:", config.EnvWebAuthnOrigins},
	} {
		if err := load(tc.rpID, tc.origins); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %v, want a refusal naming %s", name, err, tc.want)
		}
	}

	env := apiEnv(t, "127.0.0.1:8080")

	env[config.EnvWebAuthnRPName] = strings.Repeat("x", 65)
	if _, err := config.Load(lookupFrom(env)); err == nil || !strings.Contains(err.Error(), config.EnvWebAuthnRPName) {
		t.Errorf("a long relying party name: %v", err)
	}
}

func TestRegistrationIsOpenByDefaultAndTakesOnlyTwoModes(t *testing.T) {
	for _, env := range []map[string]string{nil, {config.EnvRegistration: ""}, {config.EnvRegistration: "open"}} {
		cfg, err := config.Load(lookupFrom(env))
		if err != nil || cfg.Registration != config.RegistrationOpen {
			t.Errorf("env %v: registration = %q, %v; want open", env, cfg.Registration, err)
		}
	}

	cfg, err := config.Load(lookupFrom(map[string]string{config.EnvRegistration: "invite"}))
	if err != nil || cfg.Registration != config.RegistrationInvite {
		t.Errorf("invite: registration = %q, %v", cfg.Registration, err)
	}

	for _, bad := range []string{"closed", "Invite", "INVITE", "invite-only", "true", "1"} {
		_, err := config.Load(lookupFrom(map[string]string{config.EnvRegistration: bad}))
		if err == nil || !strings.Contains(err.Error(), config.EnvRegistration) {
			t.Errorf("%q: error = %v, want a complaint naming %s", bad, err, config.EnvRegistration)
		}
	}
}

func TestTheInvitationLinkDefaultsToTheIssuerAndTakesOnlySafeAddresses(t *testing.T) {
	cfg, err := config.Load(lookupFrom(map[string]string{config.EnvJWTIssuer: "https://auth.example.test"}))
	if err != nil || cfg.InvitationURL != "https://auth.example.test" {
		t.Errorf("default link = %q, %v; want the issuer", cfg.InvitationURL, err)
	}

	cfg, err = config.Load(lookupFrom(map[string]string{config.EnvJWTIssuer: "https://auth.example.test", config.EnvInvitationURL: "https://app.example.test/login?from=invite"}))
	if err != nil || cfg.InvitationURL != "https://app.example.test/login?from=invite" {
		t.Errorf("explicit link = %q, %v", cfg.InvitationURL, err)
	}

	if cfg, err = config.Load(lookupFrom(nil)); err != nil || cfg.InvitationURL != "" {
		t.Errorf("nothing set: link = %q, %v", cfg.InvitationURL, err)
	}

	if cfg, err = config.Load(lookupFrom(map[string]string{config.EnvInvitationURL: "http://localhost:5173/"})); err != nil || cfg.InvitationURL != "http://localhost:5173/" {
		t.Errorf("a local http link = %q, %v", cfg.InvitationURL, err)
	}

	for _, bad := range []string{"app.example.test", "ftp://app.example.test", "http://app.example.test/login", "https://user:pw@app.example.test/", "https://app.example.test/#x", "javascript:alert(1)", "https:///login", "https://"} {
		_, err := config.Load(lookupFrom(map[string]string{config.EnvInvitationURL: bad}))
		if err == nil || !strings.Contains(err.Error(), config.EnvInvitationURL) || strings.Contains(err.Error(), "pw@") {
			t.Errorf("%q: error = %v", bad, err)
		}
	}
}

// adminEnv is a configuration with the admin API on, next to the public API whose relying party is example.test.
func adminEnv(t *testing.T) map[string]string {
	t.Helper()
	env := apiEnv(t, "127.0.0.1:8080")
	env[config.EnvAdminAddr] = "127.0.0.1:8081"
	env[config.EnvAdminRPID] = "admin.example.test"
	env[config.EnvAdminOrigins] = "https://admin.example.test"

	return env
}

func TestAdminIsOffByDefaultAndTakesItsOwnRelyingParty(t *testing.T) {
	cfg, err := config.Load(lookupFrom(apiEnv(t, "127.0.0.1:8080")))
	if err != nil || cfg.Admin.Enabled() || cfg.Admin.RPID != "" || cfg.Admin.Origins != nil {
		t.Fatalf("Admin = %+v, %v; want none", cfg.Admin, err)
	}

	cfg, err = config.Load(lookupFrom(adminEnv(t)))
	if err != nil || !cfg.Admin.Enabled() || cfg.Admin.Addr != "127.0.0.1:8081" || cfg.Admin.RPID != "admin.example.test" ||
		len(cfg.Admin.Origins) != 1 || cfg.Admin.Origins[0] != "https://admin.example.test" {
		t.Fatalf("Admin = %+v, %v", cfg.Admin, err)
	}
}

func TestAdminSettingsWithoutTheAddressAreAnError(t *testing.T) {
	for _, key := range []string{config.EnvAdminRPID, config.EnvAdminOrigins} {
		env := apiEnv(t, "127.0.0.1:8080")

		env[key] = "admin.example.test"
		if _, err := config.Load(lookupFrom(env)); err == nil || !strings.Contains(err.Error(), key) || !strings.Contains(err.Error(), config.EnvAdminAddr) {
			t.Errorf("%s alone: error = %v, want a refusal naming it and %s", key, err, config.EnvAdminAddr)
		}
	}
}

func TestAdminNeedsAnIPAddressAndNotAnotherListenersPort(t *testing.T) {
	for name, addr := range map[string]string{"empty host": ":8081", "host name": "localhost:8081", "no port": "127.0.0.1"} {
		env := adminEnv(t)

		env[config.EnvAdminAddr] = addr
		if _, err := config.Load(lookupFrom(env)); err == nil || !strings.Contains(err.Error(), config.EnvAdminAddr) {
			t.Errorf("%s (%s): error = %v", name, addr, err)
		}
	}

	env := adminEnv(t)

	env[config.EnvAdminAddr] = "0.0.0.0:8081"
	if _, err := config.Load(lookupFrom(env)); err == nil || !strings.Contains(err.Error(), config.EnvTrustedProxies) {
		t.Errorf("admin beyond the loopback without a proxy: error = %v", err)
	}

	env[config.EnvTrustedProxies] = "10.0.0.0/8"
	if _, err := config.Load(lookupFrom(env)); err != nil {
		t.Errorf("admin beyond the loopback behind a proxy: %v", err)
	}

	env = adminEnv(t)

	env[config.EnvAdminAddr] = "127.0.0.1:8080" // the API's own
	if _, err := config.Load(lookupFrom(env)); err == nil || !strings.Contains(err.Error(), "separate listener") {
		t.Errorf("the API's port: error = %v", err)
	}
}

func TestAdminNeedsItsRelyingPartyOriginsAndTheDatabase(t *testing.T) {
	for _, key := range []string{config.EnvAdminRPID, config.EnvAdminOrigins} {
		env := adminEnv(t)
		delete(env, key)

		if _, err := config.Load(lookupFrom(env)); err == nil || !strings.Contains(err.Error(), key) {
			t.Errorf("without %s: error = %v", key, err)
		}
	}

	env := adminEnv(t)
	delete(env, config.EnvDatabaseURL)

	if _, err := config.Load(lookupFrom(env)); err == nil || !strings.Contains(err.Error(), config.EnvDatabaseURL) {
		t.Errorf("without a database: error = %v", err)
	}
}

func TestTheAdminRelyingPartyDiffersFromTheUsersAndMatchesItsOrigins(t *testing.T) {
	load := func(rp, origins string) error {
		env := adminEnv(t)
		env[config.EnvAdminRPID], env[config.EnvAdminOrigins] = rp, origins
		_, err := config.Load(lookupFrom(env))

		return err
	}
	if err := load("example.test", "https://example.test"); err == nil || !strings.Contains(err.Error(), config.EnvWebAuthnRPID) {
		t.Errorf("the users' relying party: error = %v", err)
	}

	for name, tc := range map[string]struct{ rp, origins string }{
		"origin outside the relying party": {"admin.example.test", "https://other.test"},
		"rp with a port":                   {"admin.example.test:8443", "https://admin.example.test"},
		"rp with a scheme":                 {"https://admin.example.test", "https://admin.example.test"},
		"an IP address as rp":              {"203.0.113.9", "https://203.0.113.9"},
		"wildcard origin":                  {"admin.example.test", "*"},
		"remote plain http":                {"admin.example.test", "http://admin.example.test"},
		"an origin with a path":            {"admin.example.test", "https://admin.example.test/ui"},
	} {
		if err := load(tc.rp, tc.origins); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	if err := load("localhost", "http://localhost:5173"); err != nil {
		t.Errorf("a local development page: %v", err)
	}

	if err := load("example.test", "https://admin.example.test"); err == nil {
		t.Error("the same relying party as the users' with another origin was accepted")
	}

	if err := load("admin.example.test", "https://admin.example.test, https://ops.admin.example.test"); err != nil {
		t.Errorf("two origins: %v", err)
	}
}

func TestDatabaseSchema(t *testing.T) {
	cfg, err := config.Load(lookupFrom(map[string]string{config.EnvDatabaseSchema: "auth"}))
	if err != nil || cfg.Database.Schema != "auth" {
		t.Errorf("Schema = %q, %v", cfg.Database.Schema, err)
	}

	if cfg, err := config.Load(lookupFrom(nil)); err != nil || cfg.Database.Schema != config.DefaultDatabaseSchema {
		t.Errorf("default Schema = %q, %v", cfg.Database.Schema, err)
	}

	url := "postgres://u:p@h/db?search_path=mine"
	if cfg, err := config.Load(lookupFrom(map[string]string{config.EnvDatabaseURL: url})); err != nil || cfg.Database.Schema != "" {
		t.Errorf("Schema = %q, %v: a search_path in the URL must not be overridden by the default", cfg.Database.Schema, err)
	}

	if cfg, err := config.Load(lookupFrom(map[string]string{config.EnvDatabaseURL: url, config.EnvDatabaseSchema: "auth"})); err != nil || cfg.Database.Schema != "auth" {
		t.Errorf("Schema = %q, %v: the variable wins over the URL", cfg.Database.Schema, err)
	}

	for _, bad := range []string{"Auth", "a b", "a,b", "1abc", "pg_catalog", `a"b`} {
		_, err := config.Load(lookupFrom(map[string]string{config.EnvDatabaseSchema: bad}))
		if err == nil || !strings.Contains(err.Error(), config.EnvDatabaseSchema) {
			t.Errorf("schema %q: error = %v, want a refusal naming %s", bad, err, config.EnvDatabaseSchema)
		}
	}
}

func TestPublicProxyNetworksAreTheOnesBeyondPrivateAddresses(t *testing.T) {
	var proxies []netip.Prefix
	for _, s := range []string{"10.42.0.0/16", "172.16.5.0/24", "192.168.1.10/32", "127.0.0.1/32", "fd00::/64", "100.64.0.0/10",
		"203.0.113.0/24", "8.0.0.0/7", "2001:db8::/32", "10.0.0.0/7"} {
		proxies = append(proxies, netip.MustParsePrefix(s))
	}

	got := config.PublicProxyNetworks(proxies)

	var names []string
	for _, p := range got {
		names = append(names, p.String())
	}
	// 10.0.0.0/7 reaches 11.0.0.0/8, which is public.
	if want := "203.0.113.0/24,8.0.0.0/7,2001:db8::/32,10.0.0.0/7"; strings.Join(names, ",") != want {
		t.Errorf("PublicProxyNetworks = %s, want %s", strings.Join(names, ","), want)
	}

	if got := config.PublicProxyNetworks(nil); len(got) != 0 {
		t.Errorf("no proxies = %v", got)
	}
}
