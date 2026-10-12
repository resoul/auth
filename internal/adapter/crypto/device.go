package crypto

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"

	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/deviceauth"
)

var _ port.DeviceSecrets = Device{}

// Device issues the unguessable values of a device sign-in request. The zero value uses crypto/rand.
type Device struct {
	// Source overrides crypto/rand in tests of this package only.
	Source io.Reader
}

func (d Device) source() io.Reader {
	if d.Source == nil {
		return rand.Reader
	}
	return d.Source
}

// NewRequestID returns 16 random bytes as a request identifier.
func (d Device) NewRequestID() (deviceauth.RequestID, error) {
	var raw [16]byte
	if _, err := io.ReadFull(d.source(), raw[:]); err != nil {
		return deviceauth.RequestID{}, fmt.Errorf("generate device request id: %w", err)
	}
	return deviceauth.NewRequestID(raw), nil
}

var pairingCodeSpace = new(big.Int).Exp(big.NewInt(10), big.NewInt(deviceauth.PairingCodeLength), nil)

// NewPairingCode returns a uniformly random code of PairingCodeLength digits, leading zeros included.
func (d Device) NewPairingCode() (string, error) {
	n, err := rand.Int(d.source(), pairingCodeSpace)
	if err != nil {
		return "", fmt.Errorf("generate pairing code: %w", err)
	}
	return fmt.Sprintf("%0*d", deviceauth.PairingCodeLength, n), nil
}
