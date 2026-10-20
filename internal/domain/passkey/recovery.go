package passkey

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"go.airlance.org/auth/internal/domain/identity"
)

// Recovery code shape: 16 characters of the RFC 4648 base32 alphabet, 80 bits.
const (
	// RecoveryCodeCount is how many codes a User receives at once.
	RecoveryCodeCount = 10
	// RecoveryCodeLength is the number of characters of a code, without separators.
	RecoveryCodeLength = 16
)

const base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// ErrRecoveryCodeUsed means the code was already redeemed.
var ErrRecoveryCodeUsed = errors.New("recovery code already used")

// NormalizeRecoveryCode turns what a person typed into the canonical code: dashes and
// spaces are dropped and letters are upper-cased. It reports false for anything that
// cannot be a code.
func NormalizeRecoveryCode(s string) (string, bool) {
	var b strings.Builder

	for _, r := range s {
		switch {
		case r == '-' || r == ' ':
			continue
		case r >= 'a' && r <= 'z':
			r -= 'a' - 'A'
		}

		if r > 127 || !strings.ContainsRune(base32Alphabet, r) {
			return "", false
		}

		b.WriteRune(r)
	}

	if b.Len() != RecoveryCodeLength {
		return "", false
	}

	return b.String(), true
}

// FormatRecoveryCode groups a canonical code for display: XXXX-XXXX-XXXX-XXXX.
func FormatRecoveryCode(code string) string {
	if len(code) != RecoveryCodeLength {
		return code
	}

	return code[0:4] + "-" + code[4:8] + "-" + code[8:12] + "-" + code[12:16]
}

// RecoveryCode is a one-time proof that replaces a passkey when every key is lost. The
// server keeps the hash of the code.
type RecoveryCode struct {
	id        ID
	userID    identity.UserID
	hash      SecretHash
	createdAt time.Time
	usedAt    time.Time
}

// NewRecoveryCode validates a code issued now.
func NewRecoveryCode(id ID, userID identity.UserID, hash SecretHash, now time.Time) (*RecoveryCode, error) {
	c := &RecoveryCode{id: id, userID: userID, hash: hash, createdAt: now}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("new recovery code: %w", err)
	}

	return c, nil
}

func (c *RecoveryCode) validate() error {
	switch {
	case c.id.IsZero():
		return errors.New("id is required")
	case c.userID.IsZero():
		return errors.New("user id is required")
	case c.hash.IsZero():
		return errors.New("hash is required")
	case c.createdAt.IsZero():
		return errors.New("creation time is required")
	}

	return nil
}

// Use redeems the code once.
func (c *RecoveryCode) Use(now time.Time) error {
	if !c.usedAt.IsZero() {
		return ErrRecoveryCodeUsed
	}

	c.usedAt = now

	return nil
}

// RecoveryCodeRecord is the stored form; UsedAt is the zero time until the code is used.
type RecoveryCodeRecord struct {
	ID        ID
	UserID    identity.UserID
	Hash      SecretHash
	CreatedAt time.Time
	UsedAt    time.Time
}

// RestoreRecoveryCode rebuilds a code from storage and rejects impossible ones.
func RestoreRecoveryCode(r RecoveryCodeRecord) (*RecoveryCode, error) {
	c := &RecoveryCode{id: r.ID, userID: r.UserID, hash: r.Hash, createdAt: r.CreatedAt, usedAt: r.UsedAt}
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("restore recovery code: %w", err)
	}

	return c, nil
}

// Record returns the stored form.
func (c *RecoveryCode) Record() RecoveryCodeRecord {
	return RecoveryCodeRecord{ID: c.id, UserID: c.userID, Hash: c.hash, CreatedAt: c.createdAt, UsedAt: c.usedAt}
}

// ID returns the row identifier.
func (c *RecoveryCode) ID() ID {
	return c.id
}

// UserID returns the owner.
func (c *RecoveryCode) UserID() identity.UserID {
	return c.userID
}

// UsedAt returns when the code was redeemed, or the zero time.
func (c *RecoveryCode) UsedAt() time.Time {
	return c.usedAt
}
