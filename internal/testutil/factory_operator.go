package testutil

import (
	"fmt"

	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/operator"
	"go.airlance.org/auth/internal/domain/passkey"
)

type OperatorSpec struct {
	Email string
}

func (f *Factory) Operator(spec OperatorSpec) *operator.Operator {
	f.t.Helper()

	id, err := f.IDs.NewOperatorID()
	if err != nil {
		f.t.Fatalf("build operator id: %v", err)
	}

	raw := spec.Email
	if raw == "" {
		raw = fmt.Sprintf("ops-%s@example.test", id.String()[24:])
	}

	email, err := identity.ParseEmail(raw)
	if err != nil {
		f.t.Fatalf("build operator email %q: %v", raw, err)
	}

	o, err := operator.New(id, email, f.Clock.Now())
	if err != nil {
		f.t.Fatalf("build operator: %v", err)
	}

	return o
}

func (f *Factory) OperatorCredential(o *operator.Operator, credentialID []byte) *passkey.Credential {
	f.t.Helper()

	id, err := f.IDs.NewPasskeyID()
	if err != nil {
		f.t.Fatalf("build credential id: %v", err)
	}

	if credentialID == nil {
		credentialID = []byte("operator-credential-" + id.String())
	}

	c, err := passkey.NewCredential(passkey.NewCredentialParams{
		ID: id, UserID: o.ID().Owner(), CredentialID: credentialID, PublicKey: []byte("public-key-" + id.String()),
		Transports: []string{"internal"}, BackupEligible: true, Name: "Ops key", Now: f.Clock.Now(),
	})
	if err != nil {
		f.t.Fatalf("build operator credential: %v", err)
	}

	return c
}

func (f *Factory) Enrollment(o *operator.Operator, secret string) *operator.Enrollment {
	f.t.Helper()

	id, err := f.IDs.NewPasskeyID()
	if err != nil {
		f.t.Fatalf("build enrollment id: %v", err)
	}

	if secret == "" {
		secret = "enrollment-" + id.String()
	}

	e, err := operator.NewEnrollment(id, o.ID(), SecretHash(secret), f.Clock.Now())
	if err != nil {
		f.t.Fatalf("build enrollment: %v", err)
	}

	return e
}

func (f *Factory) OperatorSession(o *operator.Operator, secret string) *operator.Session {
	f.t.Helper()

	id, err := f.IDs.NewPasskeyID()
	if err != nil {
		f.t.Fatalf("build operator session id: %v", err)
	}

	if secret == "" {
		secret = "session-" + id.String()
	}

	s, err := operator.NewSession(id, o.ID(), SecretHash(secret), f.Clock.Now())
	if err != nil {
		f.t.Fatalf("build operator session: %v", err)
	}

	return s
}
