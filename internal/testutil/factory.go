package testutil

import (
	"crypto/sha256"
	"testing"
	"time"

	"go.airlance.org/auth/internal/domain/identity"
)

const DefaultBindingSecret = "test-binding-secret"

type Factory struct {
	t     testing.TB
	Clock *FakeClock
	IDs   *SequentialIDs
}

func NewFactory(t testing.TB, now time.Time) *Factory {
	t.Helper()
	return &Factory{t: t, Clock: NewFakeClock(now), IDs: &SequentialIDs{}}
}

func BindingHash(secret string) identity.BindingHash {
	sum := sha256.Sum256([]byte(secret))

	hash, err := identity.NewBindingHash(sum[:])
	if err != nil {
		panic(err) // unreachable: SHA-256 has the required length
	}

	return hash
}
