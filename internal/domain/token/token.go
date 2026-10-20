package token

import (
	"errors"
	"fmt"
	"time"

	"go.airlance.org/auth/internal/domain/session"
)

const hashLength = 32

// Lifecycle denials. A reused token also demands revoking the session; that is the
// caller's job, after the denial is committed.
var (
	// ErrReused means the token was already exchanged.
	ErrReused = errors.New("refresh token was already used")
	// ErrRevoked means the token was revoked before use.
	ErrRevoked = errors.New("refresh token is revoked")
	// ErrExpired means the token's lifetime ended.
	ErrExpired = errors.New("refresh token expired")
	// ErrInvalidID reports a malformed identifier.
	ErrInvalidID = errors.New("invalid token id")
)

// ID identifies a refresh token row. It is a canonical lower-case UUIDv7.
type ID struct{ value string }

// FamilyID identifies the chain of tokens descended from one login.
type FamilyID struct{ value string }

// ParseID validates the canonical UUIDv7 text form.
func ParseID(s string) (ID, error) {
	if !isUUIDv7(s) {
		return ID{}, ErrInvalidID
	}

	return ID{value: s}, nil
}

// ParseFamilyID validates the canonical UUIDv7 text form.
func ParseFamilyID(s string) (FamilyID, error) {
	if !isUUIDv7(s) {
		return FamilyID{}, ErrInvalidID
	}

	return FamilyID{value: s}, nil
}

// String returns the canonical text form.
func (id ID) String() string { return id.value }

// IsZero reports whether id is the invalid zero value.
func (id ID) IsZero() bool { return id.value == "" }

// String returns the canonical text form.
func (id FamilyID) String() string { return id.value }

// IsZero reports whether id is the invalid zero value.
func (id FamilyID) IsZero() bool { return id.value == "" }

func isUUIDv7(s string) bool {
	if len(s) != 36 {
		return false
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}

	return s[14] == '7' && (s[19] == '8' || s[19] == '9' || s[19] == 'a' || s[19] == 'b')
}

// Hash is the stored SHA-256 of a refresh secret. The secret itself is never stored.
type Hash struct {
	value [hashLength]byte
	set   bool
}

// NewHash wraps a hash of exactly 32 bytes.
func NewHash(b []byte) (Hash, error) {
	if len(b) != hashLength {
		return Hash{}, errors.New("token hash must be 32 bytes")
	}

	var h Hash
	copy(h.value[:], b)
	h.set = true

	return h, nil
}

// Bytes returns a copy of the hash.
func (h Hash) Bytes() []byte { return append([]byte(nil), h.value[:]...) }

// IsZero reports whether h is the invalid zero value.
func (h Hash) IsZero() bool { return !h.set }

// RefreshToken is one link of a family. Fields change only through its operations.
type RefreshToken struct {
	id        ID
	sessionID session.ID
	familyID  FamilyID
	parentID  ID
	hash      Hash
	createdAt time.Time
	expiresAt time.Time
	usedAt    time.Time
	revokedAt time.Time
}

// NewRoot creates the first token of a family at login.
func NewRoot(id ID, sessionID session.ID, familyID FamilyID, hash Hash, now, expiresAt time.Time) (*RefreshToken, error) {
	t := &RefreshToken{id: id, sessionID: sessionID, familyID: familyID, hash: hash, createdAt: now, expiresAt: expiresAt}
	if err := t.validate(); err != nil {
		return nil, fmt.Errorf("new refresh token: %w", err)
	}

	return t, nil
}

func (t *RefreshToken) validate() error {
	switch {
	case t.id.IsZero():
		return errors.New("id is required")
	case t.sessionID.IsZero():
		return errors.New("session id is required")
	case t.familyID.IsZero():
		return errors.New("family id is required")
	case t.hash.IsZero():
		return errors.New("hash is required")
	case t.createdAt.IsZero() || !t.expiresAt.After(t.createdAt):
		return errors.New("expiry must follow creation")
	case t.parentID == t.id && !t.id.IsZero():
		return errors.New("a token cannot be its own parent")
	}

	return nil
}

// CheckUsable reports why the token cannot be exchanged at now, or nil. A used
// token is a reuse even if it has since expired or been revoked.
func (t *RefreshToken) CheckUsable(now time.Time) error {
	switch {
	case !t.usedAt.IsZero():
		return ErrReused
	case !t.revokedAt.IsZero():
		return ErrRevoked
	case !now.Before(t.expiresAt):
		return ErrExpired
	}

	return nil
}

// Rotate exchanges the token: it is marked used and its only child is returned.
// On any denial nothing changes.
func (t *RefreshToken) Rotate(now time.Time, childID ID, childHash Hash, childExpiresAt time.Time) (*RefreshToken, error) {
	if err := t.CheckUsable(now); err != nil {
		return nil, err
	}

	child := &RefreshToken{
		id: childID, sessionID: t.sessionID, familyID: t.familyID, parentID: t.id,
		hash: childHash, createdAt: now, expiresAt: childExpiresAt,
	}
	if err := child.validate(); err != nil {
		return nil, fmt.Errorf("rotate refresh token: %w", err)
	}

	t.usedAt = now

	return child, nil
}

// Revoke forbids using the token. Revoking twice keeps the first time.
func (t *RefreshToken) Revoke(now time.Time) {
	if t.revokedAt.IsZero() {
		t.revokedAt = now
	}
}

// Record is the stored form of a RefreshToken. ParentID, UsedAt and RevokedAt are
// zero when absent.
type Record struct {
	ID        ID
	SessionID session.ID
	FamilyID  FamilyID
	ParentID  ID
	Hash      Hash
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    time.Time
	RevokedAt time.Time
}

// Restore rebuilds a token from storage and rejects impossible records.
func Restore(r Record) (*RefreshToken, error) {
	t := &RefreshToken{
		id: r.ID, sessionID: r.SessionID, familyID: r.FamilyID, parentID: r.ParentID, hash: r.Hash,
		createdAt: r.CreatedAt, expiresAt: r.ExpiresAt, usedAt: r.UsedAt, revokedAt: r.RevokedAt,
	}
	if err := t.validate(); err != nil {
		return nil, fmt.Errorf("restore refresh token: %w", err)
	}

	return t, nil
}

// Record returns the stored form.
func (t *RefreshToken) Record() Record {
	return Record{
		ID: t.id, SessionID: t.sessionID, FamilyID: t.familyID, ParentID: t.parentID, Hash: t.hash,
		CreatedAt: t.createdAt, ExpiresAt: t.expiresAt, UsedAt: t.usedAt, RevokedAt: t.revokedAt,
	}
}

// ID returns the row identifier.
func (t *RefreshToken) ID() ID { return t.id }

// SessionID returns the session the family belongs to.
func (t *RefreshToken) SessionID() session.ID { return t.sessionID }

// FamilyID returns the family.
func (t *RefreshToken) FamilyID() FamilyID { return t.familyID }

// ParentID returns the token this one replaced, or the zero ID for a root.
func (t *RefreshToken) ParentID() ID { return t.parentID }

// Hash returns the stored hash of the secret.
func (t *RefreshToken) Hash() Hash { return t.hash }

// CreatedAt returns the issue time.
func (t *RefreshToken) CreatedAt() time.Time { return t.createdAt }

// ExpiresAt returns the end of the token's life.
func (t *RefreshToken) ExpiresAt() time.Time { return t.expiresAt }

// UsedAt returns the exchange time, or the zero time.
func (t *RefreshToken) UsedAt() time.Time { return t.usedAt }

// RevokedAt returns the revocation time, or the zero time.
func (t *RefreshToken) RevokedAt() time.Time { return t.revokedAt }
