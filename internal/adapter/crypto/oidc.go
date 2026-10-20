package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/oidc"
)

var _ port.OIDCSecrets = OIDC{}

const oidcSecretBytes = 32

// OIDC issues the random secrets of the OpenID Provider: 32 random bytes in unpadded base64url, 43 characters. The
// stored hash is the SHA-256 of the decoded bytes. A value that long and that random needs no slow hash or salt. The
// zero value uses crypto/rand.
type OIDC struct {
	// Source overrides crypto/rand in tests of this package only.
	Source io.Reader
}

// NewOIDCSecret creates a secret and its hash.
func (o OIDC) NewOIDCSecret() (string, oidc.SecretHash, error) {
	source := o.Source
	if source == nil {
		source = rand.Reader
	}

	raw := make([]byte, oidcSecretBytes)
	if _, err := io.ReadFull(source, raw); err != nil {
		return "", oidc.SecretHash{}, fmt.Errorf("generate oidc secret: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(raw), sha256.Sum256(raw), nil
}

// HashOIDCSecret hashes a presented secret; any other shape is ErrInvalidOIDCSecret and nothing is compared.
func (OIDC) HashOIDCSecret(secret string) (oidc.SecretHash, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(secret)
	// The decoder skips CR and LF, so the canonical re-encoding must match the input.
	if err != nil || len(raw) != oidcSecretBytes || base64.RawURLEncoding.EncodeToString(raw) != secret {
		return oidc.SecretHash{}, port.ErrInvalidOIDCSecret
	}

	return sha256.Sum256(raw), nil
}
