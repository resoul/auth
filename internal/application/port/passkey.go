package port

import (
	"context"
	"errors"
	"time"

	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/passkey"
	"go.airlance.org/auth/internal/domain/session"
)

// Errors of the passkey repositories.
var (
	// ErrCredentialConflict reports a credential ID that is already registered.
	ErrCredentialConflict = errors.New("credential already registered")
	// ErrLastCredential reports a delete that would leave the User without a passkey.
	ErrLastCredential = errors.New("cannot delete the last credential")
)

// CredentialRepository stores WebAuthn credentials.
type CredentialRepository interface {
	// Create stores a credential. It returns ErrCredentialConflict when the credential ID exists.
	Create(ctx context.Context, c *passkey.Credential) error
	// ListByUser returns the credentials of a User, oldest first.
	ListByUser(ctx context.Context, userID identity.UserID) ([]*passkey.Credential, error)
	// GetForUpdate loads a credential by its WebAuthn credential ID and keeps it locked until
	// the transaction ends, so two assertions of one key are serialized. It first share-locks the owner, the same
	// order as every change of a user's keys, so a sign-in and a recovery cannot wait for each other. It returns
	// ErrNotFound.
	GetForUpdate(ctx context.Context, credentialID []byte) (*passkey.Credential, error)
	// Save writes the changed state of a credential loaded by GetForUpdate.
	Save(ctx context.Context, c *passkey.Credential) error
	// DeleteAllForUser removes every credential of a User and returns how many there were. Recovery uses it: the keys
	// the owner lost, or that someone else holds, must not outlive the recovery. Like Delete it queues on the user.
	DeleteAllForUser(ctx context.Context, userID identity.UserID) (int, error)
	// Delete removes one credential of a User. It returns ErrNotFound when the User has no such
	// credential and ErrLastCredential, changing nothing, when it is the only one left. Deletes
	// of one User are serialized, so two concurrent deletes cannot remove the last two.
	Delete(ctx context.Context, userID identity.UserID, id passkey.ID) error
}

// ChallengeRepository stores the state of WebAuthn ceremonies.
type ChallengeRepository interface {
	// Create stores a challenge.
	Create(ctx context.Context, c *passkey.Challenge) error
	// GetForUpdate loads a challenge and keeps it locked until the transaction ends. It returns ErrNotFound.
	GetForUpdate(ctx context.Context, id passkey.ID) (*passkey.Challenge, error)
	// Save writes the changed state of a challenge loaded by GetForUpdate.
	Save(ctx context.Context, c *passkey.Challenge) error
}

// TicketRepository stores sign-in and step-up tickets.
type TicketRepository interface {
	// Create stores a ticket. It returns ErrTicketConflict when the secret hash exists.
	Create(ctx context.Context, t *passkey.Ticket) error
	// GetByHashForUpdate loads the ticket of a presented secret and keeps it locked until the
	// transaction ends. It returns ErrNotFound.
	GetByHashForUpdate(ctx context.Context, hash passkey.SecretHash) (*passkey.Ticket, error)
	// GetByHash loads the ticket of a presented secret without locking it, so that a use case can learn whose it is and
	// lock that user first. It returns ErrNotFound.
	GetByHash(ctx context.Context, hash passkey.SecretHash) (*passkey.Ticket, error)
	// GetForUpdate loads a ticket by ID and keeps it locked until the transaction ends. It returns ErrNotFound.
	GetForUpdate(ctx context.Context, id passkey.ID) (*passkey.Ticket, error)
	// Save writes the changed state of a ticket loaded for update.
	Save(ctx context.Context, t *passkey.Ticket) error
	// RevokeAllForUser spends every live ticket of the user, so that none issued before a change of the account's
	// protection (a recovery, new recovery codes, a deleted key, a moved address, a block) can be redeemed after it.
	// The step-up tickets of the session keep stay: the session that made the change proved a key just now. The zero ID
	// keeps none. A ticket locked by another transaction is waited for.
	RevokeAllForUser(ctx context.Context, userID identity.UserID, keep session.ID, now time.Time) error
}

// ErrTicketConflict reports a ticket secret hash that already exists.
var ErrTicketConflict = errors.New("ticket conflict")

// RecoveryCodeRepository stores the recovery codes of a User.
type RecoveryCodeRepository interface {
	// Replace removes every code of the User and stores the new ones, so a fresh set always
	// supersedes the old one. Replacements of one User queue on the user row. It returns ErrTicketConflict when a hash exists.
	Replace(ctx context.Context, userID identity.UserID, codes []*passkey.RecoveryCode) error
	// GetByHashForUpdate loads the code with this hash and keeps it locked until the transaction
	// ends. It returns ErrNotFound.
	GetByHashForUpdate(ctx context.Context, hash passkey.SecretHash) (*passkey.RecoveryCode, error)
	// Save writes the changed state of a code loaded by GetByHashForUpdate.
	Save(ctx context.Context, c *passkey.RecoveryCode) error
	// CountUnused returns how many codes of the User are not used yet.
	CountUnused(ctx context.Context, userID identity.UserID) (int, error)
}

// PasskeyIDGenerator creates row identifiers (UUIDv7) of credentials, challenges, tickets and codes.
type PasskeyIDGenerator interface {
	NewPasskeyID() (passkey.ID, error)
}

// ErrInvalidTicketSecret reports a ticket secret of the wrong shape.
var ErrInvalidTicketSecret = errors.New("invalid ticket secret")

// TicketSecrets issues ticket secrets and derives the hash that is stored.
type TicketSecrets interface {
	// NewTicketSecret creates a secret and its hash.
	NewTicketSecret() (secret string, hash passkey.SecretHash, err error)
	// HashTicketSecret hashes a presented secret. A malformed secret returns ErrInvalidTicketSecret.
	HashTicketSecret(secret string) (passkey.SecretHash, error)
}

// ErrInvalidRecoveryCode reports a recovery code that cannot be one.
var ErrInvalidRecoveryCode = errors.New("invalid recovery code")

// RecoveryCodes issues recovery codes and derives the hash that is stored.
type RecoveryCodes interface {
	// NewRecoveryCodes creates passkey.RecoveryCodeCount canonical codes with their hashes.
	NewRecoveryCodes() ([]IssuedRecoveryCode, error)
	// HashRecoveryCode normalizes what a person typed and hashes it. Anything that cannot be a
	// code returns ErrInvalidRecoveryCode.
	HashRecoveryCode(typed string) (passkey.SecretHash, error)
}

// IssuedRecoveryCode is a new code in its canonical form and the hash to store.
type IssuedRecoveryCode struct {
	Code string
	Hash passkey.SecretHash
}

// Ceremony is the part of a WebAuthn ceremony a challenge keeps between two requests.
type Ceremony struct {
	// Options is the JSON the client passes to the browser or platform API.
	Options []byte
	// State is the opaque server-side state to store in the challenge.
	State []byte
}

// UserHandle is the stable, opaque identifier the authenticator keeps for a User; it is not personal data.
type UserHandle = []byte

// Subject is the User a ceremony is for.
type Subject struct {
	ID          identity.UserID
	Email       identity.Email
	Credentials []*passkey.Credential
}

// RegisteredCredential is the result of a verified registration.
type RegisteredCredential struct {
	CredentialID   []byte
	PublicKey      []byte
	AAGUID         []byte
	Transports     []string
	SignCount      uint32
	BackupEligible bool
	BackupState    bool
}

// VerifiedAssertion is the result of a verified assertion.
type VerifiedAssertion struct {
	CredentialID []byte
	UserHandle   UserHandle
	SignCount    uint32
	BackupState  bool
}

// ErrCeremonyFailed reports a registration or assertion that did not verify. It carries no
// detail: the client learns only that the proof was refused.
var ErrCeremonyFailed = errors.New("webauthn ceremony failed")

// WebAuthn runs the WebAuthn protocol steps; the application decides what a success allows.
// The library's own clock is not used for expiry: a challenge expires by the application's clock.
type WebAuthn interface {
	// BeginRegistration prepares a registration of a new credential for the subject. It
	// asks for a resident key and user verification and excludes the subject's credentials.
	BeginRegistration(subject Subject) (Ceremony, error)
	// FinishRegistration verifies the client's response against the stored state.
	FinishRegistration(subject Subject, state []byte, response []byte) (RegisteredCredential, error)
	// BeginLogin prepares an assertion with user verification. It does not name the User: the
	// authenticator offers its discoverable credentials for the relying party.
	BeginLogin() (Ceremony, error)
	// FinishLogin verifies the client's response against the stored state. lookup finds the
	// stored credential an assertion names, so the User is learned from the assertion.
	FinishLogin(state []byte, response []byte, lookup CredentialLookup) (VerifiedAssertion, error)
}

// CredentialLookup returns the stored credential for a credential ID and user handle, or
// ErrNotFound.
type CredentialLookup func(credentialID []byte, userHandle UserHandle) (*passkey.Credential, error)
