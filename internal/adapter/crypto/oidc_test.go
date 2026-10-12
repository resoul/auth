package crypto_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"airlance.org/auth/internal/adapter/crypto"
	"airlance.org/auth/internal/application/port"
)

func TestOIDCSecretsAreRandomAndHashedByTheirBytes(t *testing.T) {
	var o crypto.OIDC
	secret, hash, err := o.NewOIDCSecret()
	if err != nil || len(secret) != 43 {
		t.Fatalf("secret %q, %v: want 43 characters", secret, err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(secret)
	if sum := sha256.Sum256(raw); hash != sum {
		t.Error("the hash is not the SHA-256 of the secret's bytes")
	}
	again, err := o.HashOIDCSecret(secret)
	if err != nil || again != hash {
		t.Errorf("hashing the shown secret gives %v, %v", again, err)
	}
	other, otherHash, _ := o.NewOIDCSecret()
	if other == secret || otherHash == hash {
		t.Error("two secrets are equal")
	}
}

func TestOIDCSecretsOfTheWrongShapeAreRefusedBeforeAnyComparison(t *testing.T) {
	var o crypto.OIDC
	good, _, _ := o.NewOIDCSecret()
	for name, bad := range map[string]string{
		"empty": "", "short": "abc", "long": good + "A", "padded": good + "=", "a newline": good[:42] + "\n", "standard base64": strings.ReplaceAll(good, "-", "+") + "+",
		"spaces": " " + good[1:], "not base64": strings.Repeat("!", 43),
	} {
		if _, err := o.HashOIDCSecret(bad); !errors.Is(err, port.ErrInvalidOIDCSecret) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestOIDCSecretsFailWhenRandomnessFails(t *testing.T) {
	o := crypto.OIDC{Source: bytes.NewReader(make([]byte, 5))}
	if _, _, err := o.NewOIDCSecret(); err == nil {
		t.Error("a short random source produced a secret")
	}
}
