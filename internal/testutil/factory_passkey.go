package testutil

import (
	"crypto/sha256"
	"fmt"

	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/passkey"
	"go.airlance.org/auth/internal/domain/session"
)

func SecretHash(secret string) passkey.SecretHash {
	sum := sha256.Sum256([]byte(secret))

	hash, err := passkey.NewSecretHash(sum[:])
	if err != nil {
		panic(err) // unreachable: SHA-256 has the required length
	}

	return hash
}

type CredentialSpec struct {
	User         *identity.User
	CredentialID []byte
	Name         string
	SignCount    uint32
}

func (f *Factory) Credential(spec CredentialSpec) *passkey.Credential {
	f.t.Helper()

	if spec.User == nil {
		f.t.Fatal("build credential: User is required")
	}

	id, err := f.IDs.NewPasskeyID()
	if err != nil {
		f.t.Fatalf("build credential id: %v", err)
	}

	if spec.CredentialID == nil {
		spec.CredentialID = []byte(fmt.Sprintf("credential-%s", id))
	}

	if spec.Name == "" {
		spec.Name = "Test key"
	}

	c, err := passkey.NewCredential(passkey.NewCredentialParams{
		ID: id, UserID: spec.User.ID(), CredentialID: spec.CredentialID, PublicKey: []byte("public-key-" + id.String()),
		Transports: []string{"internal"}, SignCount: spec.SignCount, BackupEligible: true, Name: spec.Name,
		Now: f.Clock.Now(),
	})
	if err != nil {
		f.t.Fatalf("build credential: %v", err)
	}

	return c
}

type ChallengeSpec struct {
	User      *identity.User
	Purpose   passkey.ChallengePurpose
	TicketID  passkey.ID
	Session   session.ID
	Operation passkey.Operation
}

func (f *Factory) Challenge(spec ChallengeSpec) *passkey.Challenge {
	f.t.Helper()

	id, err := f.IDs.NewPasskeyID()
	if err != nil {
		f.t.Fatalf("build challenge id: %v", err)
	}

	if spec.Purpose == "" {
		spec.Purpose = passkey.ChallengeRegistration
	}

	var userID identity.UserID
	if spec.User != nil {
		userID = spec.User.ID()
	}

	c, err := passkey.NewChallenge(passkey.NewChallengeParams{
		ID: id, Purpose: spec.Purpose, UserID: userID, TicketID: spec.TicketID, SessionID: spec.Session, Operation: spec.Operation,
		Data: []byte(`{"state":"` + id.String() + `"}`),
		Now:  f.Clock.Now(),
	})
	if err != nil {
		f.t.Fatalf("build challenge: %v", err)
	}

	return c
}

type TicketSpec struct {
	User          *identity.User
	Kind          passkey.TicketKind
	Secret        string
	BindingSecret string
	Session       session.ID
	Operation     passkey.Operation
}

func (f *Factory) Ticket(spec TicketSpec) *passkey.Ticket {
	f.t.Helper()

	if spec.User == nil {
		f.t.Fatal("build ticket: User is required")
	}

	id, err := f.IDs.NewPasskeyID()
	if err != nil {
		f.t.Fatalf("build ticket id: %v", err)
	}

	if spec.Kind == "" {
		spec.Kind = passkey.TicketEnroll
	}

	if spec.Secret == "" {
		spec.Secret = "ticket-secret-" + id.String()
	}

	p := passkey.NewTicketParams{
		ID: id, Kind: spec.Kind, UserID: spec.User.ID(), SecretHash: SecretHash(spec.Secret), Now: f.Clock.Now(),
	}
	if spec.Kind == passkey.TicketStepUp {
		p.SessionID, p.Operation = spec.Session, spec.Operation
	} else {
		secret := spec.BindingSecret
		if secret == "" {
			secret = DefaultBindingSecret
		}

		p.Binding = BindingHash(secret)
	}

	t, err := passkey.NewTicket(p)
	if err != nil {
		f.t.Fatalf("build ticket: %v", err)
	}

	return t
}

func (f *Factory) RecoveryCode(user *identity.User, code string) *passkey.RecoveryCode {
	f.t.Helper()

	id, err := f.IDs.NewPasskeyID()
	if err != nil {
		f.t.Fatalf("build recovery code id: %v", err)
	}

	c, err := passkey.NewRecoveryCode(id, user.ID(), SecretHash(code), f.Clock.Now())
	if err != nil {
		f.t.Fatalf("build recovery code: %v", err)
	}

	return c
}
