package config_test

import (
	"strings"
	"testing"

	"go.airlance.org/auth/internal/config"
)

const validKeyring = `{
  "format_version": 1,
  "otp_hmac": {
    "active_kid": "otp-a",
    "keys": {
      "otp-a": {"key_file": "/run/secrets/otp-a"},
      "otp-old": {"key_file": "/run/secrets/otp-old"}
    }
  },
  "jwt_signing": {
    "active_kid": "sign-a",
    "keys": {
      "sign-a": {"key_file": "/run/secrets/sign-a.pem"},
      "sign-old": {"key_file": "/run/secrets/sign-old.pem"}
    }
  }
}`

func TestParseKeyringDocumentedExample(t *testing.T) {
	ring, err := config.ParseKeyring([]byte(validKeyring))
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}

	if got := ring.JWTSigning.Keys["sign-old"].KeyFile; got != "/run/secrets/sign-old.pem" {
		t.Errorf("sign-old key_file = %q", got)
	}
}

func TestParseKeyringPurposesAreOptional(t *testing.T) {
	ring, err := config.ParseKeyring([]byte(`{"format_version": 1}`))
	if err != nil {
		t.Fatalf("ParseKeyring: %v", err)
	}

	if ring.OTPHMAC != nil || ring.JWTSigning != nil {
		t.Errorf("ring = %+v, want no purposes", ring)
	}
}

func TestParseKeyringRejectsInvalid(t *testing.T) {
	tests := []struct {
		name string
		json string
		want string
	}{
		{"empty input", ``, "unexpected end"},
		{"not json", `format_version`, "invalid JSON"},
		{"missing version", `{}`, "format_version"},
		{"unknown version", `{"format_version": 2}`, "format_version"},
		{"unknown top field", `{"format_version": 1, "extra": true}`, "unknown field"},
		{"unknown key field", `{"format_version": 1, "otp_hmac": {"active_kid": "a", "keys": {"a": {"key_file": "f", "key": "x"}}}}`, "unknown field"},
		{"wrong type", `{"format_version": "1"}`, "invalid type"},
		{"duplicate top key", `{"format_version": 1, "format_version": 1}`, "duplicate key"},
		{"duplicate kid", `{"format_version": 1, "otp_hmac": {"active_kid": "a", "keys": {"a": {"key_file": "f"}, "a": {"key_file": "g"}}}}`, "duplicate key"},
		{"trailing data", `{"format_version": 1} {}`, "after top-level"},
		{"empty keys", `{"format_version": 1, "otp_hmac": {"active_kid": "a", "keys": {}}}`, "keys must not be empty"},
		{"active missing", `{"format_version": 1, "otp_hmac": {"active_kid": "b", "keys": {"a": {"key_file": "f"}}}}`, "active_kid"},
		{"no active kid", `{"format_version": 1, "jwt_signing": {"keys": {"a": {"key_file": "f"}}}}`, "active_kid"},
		{"no key file", `{"format_version": 1, "jwt_signing": {"active_kid": "a", "keys": {"a": {}}}}`, "no key_file"},
		{"empty kid", `{"format_version": 1, "jwt_signing": {"active_kid": "", "keys": {"": {"key_file": "f"}}}}`, "empty kid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := config.ParseKeyring([]byte(tt.json))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ParseKeyring error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestParseKeyringErrorsDoNotEchoContents(t *testing.T) {
	const secret = "s3cr3t-material"

	inputs := []string{
		`{"format_version": 1, "otp_hmac": ` + secret + `}`,
		`{"format_version": "` + secret + `"}`,
	}
	for _, in := range inputs {
		_, err := config.ParseKeyring([]byte(in))
		if err == nil {
			t.Fatalf("ParseKeyring(%q) succeeded", in)
		}

		if strings.Contains(err.Error(), secret) {
			t.Errorf("error %q echoes input", err)
		}
	}
}
