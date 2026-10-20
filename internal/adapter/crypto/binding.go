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

// Binding issues client binding secrets: 32 random bytes in unpadded base64url.
// The stored hash is SHA-256 of the decoded bytes. The zero value uses crypto/rand.
type Binding struct {
	// Source overrides crypto/rand in tests of this package only.
	Source io.Reader
}

// NewBinding creates a secret and its hash.
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

// HashBinding hashes a presented secret; any other shape is ErrInvalidBindingSecret.
func (Binding) HashBinding(secret string) (identity.BindingHash, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(secret)
	// The decoder skips CR and LF, so the canonical re-encoding must match the input.
	if err != nil || len(raw) != bindingSecretBytes || base64.RawURLEncoding.EncodeToString(raw) != secret {
		return identity.BindingHash{}, port.ErrInvalidBindingSecret
	}

	return hashBinding(raw)
}

func hashBinding(raw []byte) (identity.BindingHash, error) {
	sum := sha256.Sum256(raw)
	return identity.NewBindingHash(sum[:])
}
