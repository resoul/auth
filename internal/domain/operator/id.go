package operator

import (
	"errors"

	"go.airlance.org/auth/internal/domain/identity"
)

// ErrInvalidID reports a malformed operator identifier.
var ErrInvalidID = errors.New("invalid operator id")

// ID identifies an operator. It is a canonical lower-case UUIDv4.
type ID struct {
	value string
}

// ParseID validates the canonical UUIDv4 text form.
func ParseID(s string) (ID, error) {
	u, err := identity.ParseUserID(s)
	if err != nil {
		return ID{}, ErrInvalidID
	}

	return ID{value: u.String()}, nil
}

// String returns the canonical text form.
func (id ID) String() string { return id.value }

// IsZero reports whether id is the invalid zero value.
func (id ID) IsZero() bool { return id.value == "" }

// Owner is the identifier under which the operator's credentials and WebAuthn user handle are kept.
// The WebAuthn adapter and the credential record know one owner type; the operator tables are the
// only place an operator's owner is looked up, so it cannot be mistaken for a User.
func (id ID) Owner() identity.UserID {
	u, err := identity.ParseUserID(id.value)
	if err != nil {
		return identity.UserID{}
	}

	return u
}

// IDFromOwner is the inverse of Owner, for the owner of a credential loaded from the operator tables.
func IDFromOwner(owner identity.UserID) (ID, error) { return ParseID(owner.String()) }
