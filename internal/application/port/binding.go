package port

import (
	"errors"

	"airlance.org/auth/internal/domain/identity"
)

// ErrInvalidBindingSecret reports a client binding secret of the wrong shape.
var ErrInvalidBindingSecret = errors.New("invalid binding secret")

// BindingSecrets issues client binding secrets and derives the hash stored in flows.
type BindingSecrets interface {
	// NewBinding creates a secret for a client that has none, with its hash.
	NewBinding() (secret string, hash identity.BindingHash, err error)
	// HashBinding hashes a secret presented by a client. A malformed secret
	// returns ErrInvalidBindingSecret.
	HashBinding(secret string) (identity.BindingHash, error)
}
