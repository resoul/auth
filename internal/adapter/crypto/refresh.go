package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/token"
)

var _ port.RefreshSecrets = Refresh{}

const refreshSecretBytes = 32

// Refresh issues refresh secrets: 32 random bytes in unpadded base64url. The
// stored hash is SHA-256 of the decoded bytes. The zero value uses crypto/rand.
type Refresh struct {
	// Source overrides crypto/rand in tests of this package only.
	Source io.Reader
}

// NewRefreshSecret creates a secret and its hash.
func (r Refresh) NewRefreshSecret() (string, token.Hash, error) {
	source := r.Source
	if source == nil {
		source = rand.Reader
	}
	raw := make([]byte, refreshSecretBytes)
	if _, err := io.ReadFull(source, raw); err != nil {
		return "", token.Hash{}, fmt.Errorf("generate refresh secret: %w", err)
	}
	hash, err := hashRefresh(raw)
	if err != nil {
		return "", token.Hash{}, err
	}
	return base64.RawURLEncoding.EncodeToString(raw), hash, nil
}

// HashRefreshSecret hashes a presented secret; any other shape is ErrInvalidRefreshSecret.
func (Refresh) HashRefreshSecret(secret string) (token.Hash, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(secret)
	// The decoder skips CR and LF, so the canonical re-encoding must match the input.
	if err != nil || len(raw) != refreshSecretBytes || base64.RawURLEncoding.EncodeToString(raw) != secret {
		return token.Hash{}, port.ErrInvalidRefreshSecret
	}
	return hashRefresh(raw)
}

func hashRefresh(raw []byte) (token.Hash, error) {
	sum := sha256.Sum256(raw)
	return token.NewHash(sum[:])
}
