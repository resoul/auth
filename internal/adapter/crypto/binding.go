package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"go.airlance.org/auth/internal/domain/identity"

	"go.airlance.org/auth/internal/application/port"
)

var _ port.BindingSecrets = Binding{}

const bindingSecretBytes = 32

type Binding struct {
	Source io.Reader
}

func (b Binding) NewBinding() (string, identity.BindingHash, error) {
	source := b.Source
	if source == nil {
		source = rand.Reader
	}

	raw := make([]byte, bindingSecretBytes)
	if _, err := io.ReadFull(source, raw); err != nil {
		return "", identity.BindingHash{}, fmt.Errorf("generate binding secret: %w", err)
	}

	hash, err := hashBinding(raw)
	if err != nil {
		return "", identity.BindingHash{}, err
	}

	return base64.RawURLEncoding.EncodeToString(raw), hash, nil
}

func (Binding) HashBinding(secret string) (identity.BindingHash, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(secret)

	if err != nil || len(raw) != bindingSecretBytes || base64.RawURLEncoding.EncodeToString(raw) != secret {
		return identity.BindingHash{}, port.ErrInvalidBindingSecret
	}

	return hashBinding(raw)
}

func hashBinding(raw []byte) (identity.BindingHash, error) {
	sum := sha256.Sum256(raw)
	return identity.NewBindingHash(sum[:])
}
