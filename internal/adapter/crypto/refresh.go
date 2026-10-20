package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/token"
)

var _ port.RefreshSecrets = Refresh{}

const refreshSecretBytes = 32

type Refresh struct {
	Source io.Reader
}

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

func (Refresh) HashRefreshSecret(secret string) (token.Hash, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(secret)
	if err != nil || len(raw) != refreshSecretBytes || base64.RawURLEncoding.EncodeToString(raw) != secret {
		return token.Hash{}, port.ErrInvalidRefreshSecret
	}

	return hashRefresh(raw)
}

func hashRefresh(raw []byte) (token.Hash, error) {
	sum := sha256.Sum256(raw)
	return token.NewHash(sum[:])
}
