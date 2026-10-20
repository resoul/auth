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

type SigningKeyPEM struct {
	Private []byte
	Public  []byte
}

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
