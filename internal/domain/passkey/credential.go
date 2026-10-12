package passkey

import (
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"airlance.org/auth/internal/domain/identity"
)

// Limits of a stored credential.
const (
	// MaxCredentialIDLength is the WebAuthn limit of a credential ID.
	MaxCredentialIDLength = 1023
	// MaxNameLength is the longest label a User can give a passkey, in characters.
	MaxNameLength = 64
	// MaxPerUser bounds the credentials of one User.
	MaxPerUser = 20
)

// Errors of a credential.
var (
	// ErrCloneSuspected means the signature counter did not grow, which may be a copied authenticator.
	ErrCloneSuspected = errors.New("passkey signature counter did not increase")
	// ErrInvalidName means the label is empty after trimming or too long.
	ErrInvalidName = errors.New("invalid passkey name")
)

// transports are the AuthenticatorTransport values the credential may report.
var transports = []string{"usb", "nfc", "ble", "smart-card", "hybrid", "internal"}

// Credential is a public key registered by an authenticator for a User. The private
// key never leaves the authenticator.
type Credential struct {
	id             ID
	userID         identity.UserID
	credentialID   []byte
	publicKey      []byte
	aaguid         []byte
	transports     []string
	signCount      uint32
	backupEligible bool
	backupState    bool
	name           string
	createdAt      time.Time
	lastUsedAt     time.Time
}

// NewCredentialParams are the fields of a credential just registered.
type NewCredentialParams struct {
	ID             ID
	UserID         identity.UserID
	CredentialID   []byte
	PublicKey      []byte
	AAGUID         []byte
	Transports     []string
	SignCount      uint32
	BackupEligible bool
	BackupState    bool
	Name           string
	Now            time.Time
}

// NewCredential validates a registration result.
func NewCredential(p NewCredentialParams) (*Credential, error) {
	c := &Credential{
		id: p.ID, userID: p.UserID, credentialID: slices.Clone(p.CredentialID), publicKey: slices.Clone(p.PublicKey),
		aaguid: slices.Clone(p.AAGUID), transports: normalizeTransports(p.Transports), signCount: p.SignCount,
		backupEligible: p.BackupEligible, backupState: p.BackupState, name: strings.TrimSpace(p.Name),
		createdAt: p.Now,
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("new credential: %w", err)
	}
	return c, nil
}

func (c *Credential) validate() error {
	switch {
	case c.id.IsZero():
		return errors.New("id is required")
	case c.userID.IsZero():
		return errors.New("user id is required")
	case len(c.credentialID) == 0 || len(c.credentialID) > MaxCredentialIDLength:
		return errors.New("credential id length is out of range")
	case len(c.publicKey) == 0:
		return errors.New("public key is required")
	case len(c.aaguid) != 0 && len(c.aaguid) != 16:
		return errors.New("aaguid must be 16 bytes")
	case c.backupState && !c.backupEligible:
		return errors.New("a credential that is not backup eligible cannot be backed up")
	case c.createdAt.IsZero():
		return errors.New("creation time is required")
	case !validName(c.name):
		return ErrInvalidName
	}
	return nil
}

// ValidName reports whether a label can be stored: one to MaxNameLength characters, no control characters.
func ValidName(name string) bool { return validName(strings.TrimSpace(name)) }

func validName(name string) bool {
	return name != "" && utf8.RuneCountInString(name) <= MaxNameLength && utf8.ValidString(name) &&
		!strings.ContainsFunc(name, func(r rune) bool { return r < ' ' || r == 0x7f })
}

// normalizeTransports keeps the known transports once each, in a stable order.
func normalizeTransports(in []string) []string {
	var out []string
	for _, t := range transports {
		if slices.Contains(in, t) {
			out = append(out, t)
		}
	}
	return out
}

// RecordUse applies a successful assertion. A counter that did not grow is refused
// unless both counters are zero, which is what synced passkeys report; the credential
// is not changed then.
func (c *Credential) RecordUse(now time.Time, signCount uint32, backupState bool) error {
	if (c.signCount != 0 || signCount != 0) && signCount <= c.signCount {
		return ErrCloneSuspected
	}
	if backupState && !c.backupEligible {
		return errors.New("record use: a credential that is not backup eligible cannot be backed up")
	}
	c.signCount = signCount
	c.backupState = backupState
	c.lastUsedAt = now
	return nil
}

// Rename changes the label.
func (c *Credential) Rename(name string) error {
	name = strings.TrimSpace(name)
	if !validName(name) {
		return ErrInvalidName
	}
	c.name = name
	return nil
}

// CredentialRecord is the stored form of a credential. LastUsedAt is the zero time
// until the first use.
type CredentialRecord struct {
	ID             ID
	UserID         identity.UserID
	CredentialID   []byte
	PublicKey      []byte
	AAGUID         []byte
	Transports     []string
	SignCount      uint32
	BackupEligible bool
	BackupState    bool
	Name           string
	CreatedAt      time.Time
	LastUsedAt     time.Time
}

// RestoreCredential rebuilds a credential from storage and rejects impossible ones.
func RestoreCredential(r CredentialRecord) (*Credential, error) {
	c := &Credential{
		id: r.ID, userID: r.UserID, credentialID: slices.Clone(r.CredentialID), publicKey: slices.Clone(r.PublicKey),
		aaguid: slices.Clone(r.AAGUID), transports: slices.Clone(r.Transports), signCount: r.SignCount,
		backupEligible: r.BackupEligible, backupState: r.BackupState, name: r.Name,
		createdAt: r.CreatedAt, lastUsedAt: r.LastUsedAt,
	}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("restore credential: %w", err)
	}
	return c, nil
}

// Record returns the stored form.
func (c *Credential) Record() CredentialRecord {
	return CredentialRecord{
		ID: c.id, UserID: c.userID, CredentialID: slices.Clone(c.credentialID), PublicKey: slices.Clone(c.publicKey),
		AAGUID: slices.Clone(c.aaguid), Transports: slices.Clone(c.transports), SignCount: c.signCount,
		BackupEligible: c.backupEligible, BackupState: c.backupState, Name: c.name,
		CreatedAt: c.createdAt, LastUsedAt: c.lastUsedAt,
	}
}

// ID returns the row identifier.
func (c *Credential) ID() ID { return c.id }

// UserID returns the owner.
func (c *Credential) UserID() identity.UserID { return c.userID }

// CredentialID returns the WebAuthn credential ID.
func (c *Credential) CredentialID() []byte { return slices.Clone(c.credentialID) }

// PublicKey returns the COSE public key.
func (c *Credential) PublicKey() []byte { return slices.Clone(c.publicKey) }

// AAGUID returns the authenticator model identifier, or nil.
func (c *Credential) AAGUID() []byte { return slices.Clone(c.aaguid) }

// Transports returns the reported transports.
func (c *Credential) Transports() []string { return slices.Clone(c.transports) }

// SignCount returns the last signature counter.
func (c *Credential) SignCount() uint32 { return c.signCount }

// BackupEligible reports whether the credential may be synced.
func (c *Credential) BackupEligible() bool { return c.backupEligible }

// BackupState reports whether the credential is currently backed up.
func (c *Credential) BackupState() bool { return c.backupState }

// Name returns the label.
func (c *Credential) Name() string { return c.name }

// CreatedAt returns the registration time.
func (c *Credential) CreatedAt() time.Time { return c.createdAt }

// LastUsedAt returns the last successful assertion, or the zero time.
func (c *Credential) LastUsedAt() time.Time { return c.lastUsedAt }

// UserHandle is the opaque identifier an authenticator keeps for a User: the 16 bytes of the
// User ID. It is not personal data and never changes, so a credential is tied to its owner
// whatever happens to the email.
func UserHandle(id identity.UserID) []byte {
	raw, err := hex.DecodeString(strings.ReplaceAll(id.String(), "-", ""))
	if err != nil {
		panic(fmt.Sprintf("user id %q is not a uuid: %v", id, err)) // unreachable: UserID is validated
	}
	return raw
}
