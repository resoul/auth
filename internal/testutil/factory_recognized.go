package testutil

import (
	"airlance.org/auth/internal/domain/identity"
)

// RecognizedSpec describes a RecognizedClient. User is required: the link is
// explicit and no user is created implicitly.
type RecognizedSpec struct {
	User *identity.User
	// BindingSecret defaults to DefaultBindingSecret.
	BindingSecret string
}

// RecognizedClient builds a record verified at the factory clock time.
func (f *Factory) RecognizedClient(spec RecognizedSpec) *identity.RecognizedClient {
	f.t.Helper()
	if spec.User == nil {
		f.t.Fatal("build recognized client: User is required")
	}
	secret := spec.BindingSecret
	if secret == "" {
		secret = DefaultBindingSecret
	}
	id, err := f.IDs.NewRecognizedClientID()
	if err != nil {
		f.t.Fatalf("build recognized client id: %v", err)
	}
	c, err := identity.NewRecognizedClient(id, spec.User.ID(), spec.User.Email(), BindingHash(secret), f.Clock.Now())
	if err != nil {
		f.t.Fatalf("build recognized client: %v", err)
	}
	return c
}
