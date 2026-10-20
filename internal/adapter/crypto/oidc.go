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

type OIDC struct {
	Source io.Reader
}

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

func (OIDC) HashOIDCSecret(secret string) (oidc.SecretHash, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(secret)
	if err != nil || len(raw) != oidcSecretBytes || base64.RawURLEncoding.EncodeToString(raw) != secret {
		return oidc.SecretHash{}, port.ErrInvalidOIDCSecret
	}

	return sha256.Sum256(raw), nil
}
