package port

import (
	"errors"

	"airlance.org/auth/internal/domain/token"
)

// ErrInvalidRefreshSecret reports a refresh secret of the wrong shape.
var ErrInvalidRefreshSecret = errors.New("invalid refresh secret")

// RefreshSecrets issues refresh secrets and derives the hash that is stored.
type RefreshSecrets interface {
	// NewRefreshSecret creates a secret and its hash.
	NewRefreshSecret() (secret string, hash token.Hash, err error)
	// HashRefreshSecret hashes a presented secret. A malformed secret returns
	// ErrInvalidRefreshSecret.
	HashRefreshSecret(secret string) (token.Hash, error)
}
