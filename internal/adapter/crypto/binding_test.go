package crypto_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"airlance.org/auth/internal/adapter/crypto"
	"airlance.org/auth/internal/application/port"
)

func TestNewBindingIssuesHashableSecret(t *testing.T) {
	var b crypto.Binding
	secret, hash, err := b.NewBinding()
	if err != nil {
		t.Fatalf("NewBinding: %v", err)
	}
	if len(secret) != 43 {
		t.Errorf("secret %q has %d chars, want 43 (32 bytes in base64url)", secret, len(secret))
	}
	again, err := b.HashBinding(secret)
	if err != nil || again != hash {
		t.Errorf("HashBinding(secret) = %v, %v; want the issued hash", again, err)
	}
	other, otherHash, _ := b.NewBinding()
	if other == secret || otherHash == hash {
		t.Error("two clients got the same binding")
	}
}

func TestBindingHashIsSHA256OfDecodedBytes(t *testing.T) {
	raw := seq(0, 32)
	secret, hash, err := crypto.Binding{Source: bytes.NewReader(raw)}.NewBinding()
	if err != nil {
		t.Fatal(err)
	}
	if secret != "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8" {
		t.Errorf("secret = %q", secret)
	}
	want := sha256.Sum256(raw)
	if !bytes.Equal(hash.Bytes(), want[:]) {
		t.Errorf("hash = %x, want %x", hash.Bytes(), want)
	}
}

func TestHashBindingRejectsMalformedSecrets(t *testing.T) {
	valid := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	for name, in := range map[string]string{
		"empty":              "",
		"short":              valid[:42],
		"long":               valid + "A",
		"padded":             valid + "=",
		"std alphabet":       strings.Repeat("+", 43),
		"whitespace":         " " + valid[1:],
		"newline":            valid + "\n",
		"non-canonical tail": valid[:42] + "B", // spare bits of the last char must be zero
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := (crypto.Binding{}).HashBinding(in); !errors.Is(err, port.ErrInvalidBindingSecret) {
				t.Errorf("error = %v, want ErrInvalidBindingSecret", err)
			}
		})
	}
	if _, err := (crypto.Binding{}).HashBinding(valid); err != nil {
		t.Errorf("valid secret rejected: %v", err)
	}
}

func TestNewBindingFailsWithoutRandomness(t *testing.T) {
	boom := errors.New("entropy unavailable")
	for name, source := range map[string]interface{ Read([]byte) (int, error) }{
		"error": failingReader{err: boom}, "short": bytes.NewReader(make([]byte, 31)),
	} {
		secret, hash, err := crypto.Binding{Source: source}.NewBinding()
		if err == nil || secret != "" || !hash.IsZero() {
			t.Errorf("%s: NewBinding = %q, %v, %v; want error and nothing", name, secret, hash, err)
		}
	}
}
