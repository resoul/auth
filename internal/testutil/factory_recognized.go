package testutil

import (
	"go.airlance.org/auth/internal/domain/identity"
)

type RecognizedSpec struct {
	User          *identity.User
	BindingSecret string
	Email         identity.Email
}

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

	email := spec.Email
	if email.IsZero() {
		email = spec.User.Email()
	}

	c, err := identity.NewRecognizedClient(id, spec.User.ID(), email, BindingHash(secret), f.Clock.Now())
	if err != nil {
		f.t.Fatalf("build recognized client: %v", err)
	}

	return c
}
