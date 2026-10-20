package testutil

import (
	"crypto/sha256"
	"testing"
	"time"

	"go.airlance.org/auth/internal/domain/identity"
)

// DefaultBindingSecret is the client binding secret of flows built without BindingSecret.
const DefaultBindingSecret = "test-binding-secret"

// Factory builds valid domain objects through domain operations. It only builds;
// persisting is a separate, explicit step added with the repositories.
// Every test creates its own Factory; nothing is shared between tests.
type Factory struct {
	t     testing.TB
	Clock *FakeClock
	IDs   *SequentialIDs
}

// NewFactory returns a Factory whose clock starts at now.
func NewFactory(t testing.TB, now time.Time) *Factory {
	t.Helper()
	return &Factory{t: t, Clock: NewFakeClock(now), IDs: &SequentialIDs{}}
}

// BindingHash returns the stored hash for a client binding secret.
func BindingHash(secret string) identity.BindingHash {
	sum := sha256.Sum256([]byte(secret))

	hash, err := identity.NewBindingHash(sum[:])
	if err != nil {
		panic(err) // unreachable: SHA-256 has the required length
	}

	return hash
}
