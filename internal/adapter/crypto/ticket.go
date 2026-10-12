package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/passkey"
)

var _ port.TicketSecrets = Ticket{}

const ticketSecretBytes = 32

// Ticket issues ticket secrets: 32 random bytes in unpadded base64url. The stored hash is
// SHA-256 of the decoded bytes. The zero value uses crypto/rand.
type Ticket struct {
	// Source overrides crypto/rand in tests of this package only.
	Source io.Reader
}

// NewTicketSecret creates a secret and its hash.
func (t Ticket) NewTicketSecret() (string, passkey.SecretHash, error) {
	source := t.Source
	if source == nil {
		source = rand.Reader
	}
	raw := make([]byte, ticketSecretBytes)
	if _, err := io.ReadFull(source, raw); err != nil {
		return "", passkey.SecretHash{}, fmt.Errorf("generate ticket secret: %w", err)
	}
	hash, err := hashSecret(raw)
	if err != nil {
		return "", passkey.SecretHash{}, err
	}
	return base64.RawURLEncoding.EncodeToString(raw), hash, nil
}

// HashTicketSecret hashes a presented secret; any other shape is ErrInvalidTicketSecret.
func (Ticket) HashTicketSecret(secret string) (passkey.SecretHash, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(secret)
	// The decoder skips CR and LF, so the canonical re-encoding must match the input.
	if err != nil || len(raw) != ticketSecretBytes || base64.RawURLEncoding.EncodeToString(raw) != secret {
		return passkey.SecretHash{}, port.ErrInvalidTicketSecret
	}
	return hashSecret(raw)
}

func hashSecret(raw []byte) (passkey.SecretHash, error) {
	sum := sha256.Sum256(raw)
	return passkey.NewSecretHash(sum[:])
}
