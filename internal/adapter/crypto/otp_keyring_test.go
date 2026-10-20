package crypto_test

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.airlance.org/auth/internal/adapter/crypto"
)

func keyFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func b64(key []byte) string { return base64.StdEncoding.EncodeToString(key) }

func TestLoadOTPKeyring(t *testing.T) {
	files := map[string]string{
		"otp-a":   keyFile(t, b64(vectorKey)+"\n"),
		"otp-old": keyFile(t, "  "+b64(vectorOther)+" \r\n"),
	}

	ring, err := crypto.LoadOTPKeyring("otp-a", files)
	if err != nil {
		t.Fatalf("LoadOTPKeyring: %v", err)
	}

	if ring.ActiveKID() != "otp-a" || strings.Join(ring.KIDs(), ",") != "otp-a,otp-old" {
		t.Errorf("active=%q kids=%v", ring.ActiveKID(), ring.KIDs())
	}

	// The loaded keys derive the same code as keys given directly.
	otp, err := crypto.NewOTP(ring, nil)
	if err != nil {
		t.Fatal(err)
	}

	got, err := otp.Code(flow(t, "login", 1, vectorSalt, "otp-a"))
	if err != nil || got != "43158632" {
		t.Errorf("Code = %q, %v; want 43158632", got, err)
	}
}

func TestLoadOTPKeyringRejectsBadFiles(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name string
		path string
	}{
		{"missing file", filepath.Join(dir, "absent")},
		{"directory", dir},
		{"empty", keyFile(t, "")},
		{"not base64", keyFile(t, "this is not base64!")},
		{"url alphabet", keyFile(t, strings.NewReplacer("+", "-", "/", "_").Replace(b64(seq(250, 32))))},
		{"unpadded", keyFile(t, strings.TrimRight(b64(vectorKey), "="))},
		{"short key", keyFile(t, b64(vectorKey[:31]))},
		{"long key", keyFile(t, b64(append(append([]byte(nil), vectorKey...), 1)))},
		{"raw bytes", keyFile(t, string(vectorKey))},
		{"huge file", keyFile(t, strings.Repeat("A", 4096))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := crypto.LoadOTPKeyring("k", map[string]string{"k": tt.path})
			if err == nil {
				t.Fatal("LoadOTPKeyring succeeded")
			}

			if !strings.Contains(err.Error(), `"k"`) {
				t.Errorf("error %q does not name the kid", err)
			}
		})
	}
}

func TestLoadOTPKeyringErrorsDoNotEchoContents(t *testing.T) {
	const secret = "c2VjcmV0LW1hdGVyaWFs-not-a-valid-key"

	_, err := crypto.LoadOTPKeyring("k", map[string]string{"k": keyFile(t, secret)})
	if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "c2VjcmV0") {
		t.Errorf("error = %v; must not echo key file contents", err)
	}
}

func TestLoadOTPKeyringRequiresEveryReferencedKey(t *testing.T) {
	files := map[string]string{
		"otp-a":   keyFile(t, b64(vectorKey)),
		"otp-old": filepath.Join(t.TempDir(), "gone"),
	}
	if _, err := crypto.LoadOTPKeyring("otp-a", files); err == nil {
		t.Error("a missing historical key must fail loading")
	}
}

func TestNewOTPKeyringValidation(t *testing.T) {
	key := vectorKey

	tests := []struct {
		name   string
		active string
		keys   map[string][]byte
	}{
		{"no keys", "a", nil},
		{"active missing", "b", map[string][]byte{"a": key}},
		{"empty active", "", map[string][]byte{"a": key}},
		{"empty kid", "", map[string][]byte{"": key}},
		{"short key", "a", map[string][]byte{"a": key[:16]}},
		{"nil key", "a", map[string][]byte{"a": nil}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := crypto.NewOTPKeyring(tt.active, tt.keys); err == nil {
				t.Error("NewOTPKeyring succeeded")
			}
		})
	}
}

func TestNewOTPKeyringCopiesKeyMaterial(t *testing.T) {
	key := append([]byte(nil), vectorKey...)

	ring, err := crypto.NewOTPKeyring("k", map[string][]byte{"k": key})
	if err != nil {
		t.Fatal(err)
	}

	otp, _ := crypto.NewOTP(ring, nil)
	f := flow(t, "login", 1, vectorSalt, "k")
	before, _ := otp.Code(f)

	for i := range key {
		key[i] = 0
	}

	after, _ := otp.Code(f)
	if before != after {
		t.Error("keyring aliases the caller's key slice")
	}
}
