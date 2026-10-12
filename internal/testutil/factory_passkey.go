package testutil

import (
	"crypto/sha256"
	"fmt"

	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/domain/passkey"
	"airlance.org/auth/internal/domain/session"
)

// SecretHash returns the stored hash of a ticket secret or recovery code.
func SecretHash(secret string) passkey.SecretHash {
	sum := sha256.Sum256([]byte(secret))
	hash, err := passkey.NewSecretHash(sum[:])
	if err != nil {
		panic(err) // unreachable: SHA-256 has the required length
	}
	return hash
}

// CredentialSpec describes a credential. User is required.
type CredentialSpec struct {
	User *identity.User
	// CredentialID defaults to a distinct value per credential.
	CredentialID []byte
	Name         string
	SignCount    uint32
}

// Credential builds a credential registered at the factory clock time.
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

// ChallengeSpec describes a challenge. User may be nil only for a login.
type ChallengeSpec struct {
	User     *identity.User
	Purpose  passkey.ChallengePurpose
	TicketID passkey.ID
	// Session and Operation are required for a step-up challenge.
	Session   session.ID
	Operation passkey.Operation
}

// Challenge builds a challenge issued at the factory clock time.
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

// TicketSpec describes a ticket and the secret whose hash it keeps. User is required.
type TicketSpec struct {
	User *identity.User
	Kind passkey.TicketKind
	// Secret defaults to a distinct value per ticket.
	Secret string
	// BindingSecret defaults to DefaultBindingSecret; used by enroll and second-factor tickets.
	BindingSecret string
	// Session and Operation are required for a step-up ticket.
	Session   session.ID
	Operation passkey.Operation
}

// Ticket builds a ticket issued at the factory clock time.
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

// RecoveryCode builds an unused recovery code of the user for the code text.
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
