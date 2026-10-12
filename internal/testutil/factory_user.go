package testutil

import (
	"fmt"

	"airlance.org/auth/internal/domain/identity"
)

// UserSpec overrides the fields a scenario cares about.
type UserSpec struct {
	// Email defaults to a unique address under example.test.
	Email string
}

// User builds a User confirmed at the factory clock time.
func (f *Factory) User(spec UserSpec) *identity.User {
	f.t.Helper()
	id, err := f.IDs.NewUserID()
	if err != nil {
		f.t.Fatalf("build user id: %v", err)
	}
	raw := spec.Email
	if raw == "" {
		raw = fmt.Sprintf("user-%s@example.test", id.String()[24:])
	}
	email, err := identity.ParseEmail(raw)
	if err != nil {
		f.t.Fatalf("build user email %q: %v", raw, err)
	}
	user, err := identity.NewUser(id, email, f.Clock.Now())
	if err != nil {
		f.t.Fatalf("build user: %v", err)
	}
	return user
}
