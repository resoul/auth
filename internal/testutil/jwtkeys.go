package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// SigningKeyPEM is a freshly generated ES256 key in the two file formats the
// keyring accepts.
type SigningKeyPEM struct {
	// Private is PKCS#8 ("PRIVATE KEY"); Public is PKIX ("PUBLIC KEY").
	Private []byte
	Public  []byte
}

// NewSigningKeyPEM generates a P-256 key pair.
func NewSigningKeyPEM(t testing.TB) SigningKeyPEM {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	return pemOf(t, key)
}

func pemOf(t testing.TB, key *ecdsa.PrivateKey) SigningKeyPEM {
	t.Helper()
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return SigningKeyPEM{
		Private: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}),
		Public:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}),
	}
}

// WriteFile writes content under a fresh temporary directory and returns the path.
func WriteFile(t testing.TB, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

var (
	rsaOnce sync.Once
	rsaPEM  SigningKeyPEM
)

// NewRSAKeyPEM returns an RSA-2048 key pair in the two file formats the OIDC keyring accepts. Generating one takes
// a moment, so a test process makes it once and every test shares it: nothing in a test depends on the key being new.
func NewRSAKeyPEM(t testing.TB) SigningKeyPEM {
	t.Helper()
	rsaOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate rsa key: %v", err)
		}
		private, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		public, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		rsaPEM = SigningKeyPEM{
			Private: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}),
			Public:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}),
		}
	})
	if rsaPEM.Private == nil {
		t.Fatal("the shared rsa key could not be generated")
	}
	return rsaPEM
}
