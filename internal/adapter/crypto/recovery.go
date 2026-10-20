package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"io"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/passkey"
)

var _ port.RecoveryCodes = Recovery{}

const recoveryCodeBytes = 10

var recoveryEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

type Recovery struct {
	Source io.Reader
}

func (r Recovery) NewRecoveryCodes() ([]port.IssuedRecoveryCode, error) {
	source := r.Source
	if source == nil {
		source = rand.Reader
	}

	seen := map[string]bool{}

	out := make([]port.IssuedRecoveryCode, 0, passkey.RecoveryCodeCount)
	for len(out) < passkey.RecoveryCodeCount {
		raw := make([]byte, recoveryCodeBytes)
		if _, err := io.ReadFull(source, raw); err != nil {
			return nil, fmt.Errorf("generate recovery code: %w", err)
		}

		code := recoveryEncoding.EncodeToString(raw)
		if seen[code] {
			continue
		}

		seen[code] = true

		hash, err := hashCode(code)
		if err != nil {
			return nil, err
		}

		out = append(out, port.IssuedRecoveryCode{Code: code, Hash: hash})
	}

	return out, nil
}

func (Recovery) HashRecoveryCode(typed string) (passkey.SecretHash, error) {
	code, ok := passkey.NormalizeRecoveryCode(typed)
	if !ok {
		return passkey.SecretHash{}, port.ErrInvalidRecoveryCode
	}

	return hashCode(code)
}

func hashCode(code string) (passkey.SecretHash, error) {
	sum := sha256.Sum256([]byte(code))
	return passkey.NewSecretHash(sum[:])
}
