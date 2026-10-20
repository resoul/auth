package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/passkey"
)

var _ port.TicketSecrets = Ticket{}

const ticketSecretBytes = 32

type Ticket struct {
	Source io.Reader
}

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

func (Ticket) HashTicketSecret(secret string) (passkey.SecretHash, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(secret)
	if err != nil || len(raw) != ticketSecretBytes || base64.RawURLEncoding.EncodeToString(raw) != secret {
		return passkey.SecretHash{}, port.ErrInvalidTicketSecret
	}

	return hashSecret(raw)
}

func hashSecret(raw []byte) (passkey.SecretHash, error) {
	sum := sha256.Sum256(raw)
	return passkey.NewSecretHash(sum[:])
}
