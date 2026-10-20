package bootstrap_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.airlance.org/auth/internal/bootstrap"
	"go.airlance.org/auth/internal/config"
	"go.airlance.org/auth/internal/testutil"
)

func TestRunEmptyServiceStartsAndStopsOnCancel(t *testing.T) {
	var out bytes.Buffer

	cfg := config.Config{
		Log:             config.LogConfig{Format: config.LogFormatText},
		ShutdownTimeout: time.Second,
	}
	logger := bootstrap.NewLogger(&out, cfg.Log)

	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan error, 1)
	go func() { done <- bootstrap.Run(ctx, cfg, logger) }()

	cancel()

	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}

	for _, want := range []string{"keyring not configured", "service started", "service stopped"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("log %q does not contain %q", out.String(), want)
		}
	}
}

func TestRunLogsKeyringKIDsWithoutPaths(t *testing.T) {
	dir := t.TempDir()
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	refs := map[string]config.KeyRef{}

	for _, kid := range []string{"otp-a", "otp-old"} {
		path := filepath.Join(dir, kid)
		if err := os.WriteFile(path, []byte(key), 0o600); err != nil {
			t.Fatal(err)
		}

		refs[kid] = config.KeyRef{KeyFile: path}
	}

	var out bytes.Buffer

	cfg := config.Config{
		Log:             config.LogConfig{Format: config.LogFormatJSON},
		ShutdownTimeout: time.Second,
		Keyring: &config.Keyring{
			FormatVersion: config.KeyringFormatVersion,
			OTPHMAC:       &config.KeySet{ActiveKID: "otp-a", Keys: refs},
		},
	}
	logger := bootstrap.NewLogger(&out, cfg.Log)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if err := bootstrap.Run(ctx, cfg, logger); err != nil {
		t.Fatalf("Run: %v", err)
	}

	log := out.String()
	if !strings.Contains(log, `"purpose":"otp_hmac"`) || !strings.Contains(log, `"kids":["otp-a","otp-old"]`) {
		t.Errorf("log lacks purpose/kids: %s", log)
	}

	if strings.Contains(log, dir) || strings.Contains(log, key) {
		t.Errorf("log leaks key file path or material: %s", log)
	}
}

func writeKeyring(t *testing.T, keyContent string) config.Config {
	t.Helper()

	path := filepath.Join(t.TempDir(), "otp-a")
	if err := os.WriteFile(path, []byte(keyContent), 0o600); err != nil {
		t.Fatal(err)
	}

	return config.Config{
		Log:             config.LogConfig{Format: config.LogFormatText},
		ShutdownTimeout: time.Second,
		Keyring: &config.Keyring{
			FormatVersion: config.KeyringFormatVersion,
			OTPHMAC:       &config.KeySet{ActiveKID: "otp-a", Keys: map[string]config.KeyRef{"otp-a": {KeyFile: path}}},
		},
	}
}

func TestRunLoadsOTPKeyFiles(t *testing.T) {
	cfg := writeKeyring(t, base64.StdEncoding.EncodeToString(make([]byte, 32)))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if err := bootstrap.Run(ctx, cfg, bootstrap.NewLogger(io.Discard, cfg.Log)); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestRunRefusesToStartWithBrokenOTPKey(t *testing.T) {
	const secret = "not-a-key-but-secret-looking-text"

	cfg := writeKeyring(t, secret)

	err := bootstrap.Run(t.Context(), cfg, bootstrap.NewLogger(io.Discard, cfg.Log))
	if err == nil || !strings.Contains(err.Error(), "otp-a") {
		t.Fatalf("Run error = %v, want failure naming the kid", err)
	}

	if strings.Contains(err.Error(), secret) {
		t.Errorf("error %q echoes key file contents", err)
	}
}

func jwtConfig(t *testing.T, privatePEM []byte) config.Config {
	t.Helper()
	path := testutil.WriteFile(t, "sign-a.pem", privatePEM)

	return config.Config{
		Log:             config.LogConfig{Format: config.LogFormatText},
		ShutdownTimeout: time.Second,
		JWT:             config.JWTConfig{Issuer: "https://auth.example.test", Audience: "example", AccessTTL: 5 * time.Minute},
		Keyring: &config.Keyring{
			FormatVersion: config.KeyringFormatVersion,
			JWTSigning:    &config.KeySet{ActiveKID: "sign-a", Keys: map[string]config.KeyRef{"sign-a": {KeyFile: path}}},
		},
	}
}

func TestRunLoadsJWTKeys(t *testing.T) {
	cfg := jwtConfig(t, testutil.NewSigningKeyPEM(t).Private)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if err := bootstrap.Run(ctx, cfg, bootstrap.NewLogger(io.Discard, cfg.Log)); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestRunRefusesToStartWithoutAUsableJWTSigningKey(t *testing.T) {
	keys := testutil.NewSigningKeyPEM(t)
	for name, content := range map[string][]byte{
		"public key as the active key": keys.Public,
		"not a key":                    []byte("secret-looking-text"),
	} {
		t.Run(name, func(t *testing.T) {
			cfg := jwtConfig(t, content)

			err := bootstrap.Run(t.Context(), cfg, bootstrap.NewLogger(io.Discard, cfg.Log))
			if err == nil || !strings.Contains(err.Error(), "sign-a") {
				t.Fatalf("Run error = %v, want a failure naming the kid", err)
			}

			if strings.Contains(err.Error(), "secret-looking-text") {
				t.Errorf("error %q echoes the key file", err)
			}
		})
	}
}
