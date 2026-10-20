package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/authflow"
)

var (
	_ port.OTPGenerations = (*OTP)(nil)
	_ port.OTPCodes       = (*OTP)(nil)
)

var (
	ErrUnknownOTPKey = errors.New("unknown otp key id")
	ErrNoOTPSalt     = errors.New("flow has no otp salt")
)

const (
	otpFormatDomain = "go.airlance.org/auth/otp/v1"
	otpDigits       = 8
	otpModulus      = 100_000_000
)

type OTP struct {
	ring   *OTPKeyring
	random io.Reader
}

func NewOTP(ring *OTPKeyring, random io.Reader) (*OTP, error) {
	if ring == nil {
		return nil, errors.New("new otp: keyring is required")
	}

	if random == nil {
		random = rand.Reader
	}

	return &OTP{ring: ring, random: random}, nil
}

func (o *OTP) NewGeneration() (port.OTPGeneration, error) {
	salt := make([]byte, authflow.SaltLength)
	if _, err := io.ReadFull(o.random, salt); err != nil {
		return port.OTPGeneration{}, fmt.Errorf("generate otp salt: %w", err)
	}

	return port.OTPGeneration{Salt: salt, KeyID: o.ring.ActiveKID()}, nil
}

func (o *OTP) Code(f *authflow.Flow) (string, error) {
	return o.derive(f.KeyID(), f.ID().String(), string(f.Purpose()), f.Generation(), f.Salt())
}

func (o *OTP) Matches(f *authflow.Flow, submitted string) (bool, error) {
	want, err := o.Code(f)
	if err != nil {
		return false, err
	}

	if !isCode(submitted) {
		return false, nil
	}

	return subtle.ConstantTimeCompare([]byte(want), []byte(submitted)) == 1, nil
}

func (o *OTP) derive(keyID, flowID, purpose string, generation uint64, salt []byte) (string, error) {
	if len(salt) != authflow.SaltLength {
		return "", ErrNoOTPSalt
	}

	key, ok := o.ring.key(keyID)
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrUnknownOTPKey, keyID)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(encodeOTPMessage(flowID, purpose, generation, salt))
	value := binary.BigEndian.Uint64(mac.Sum(nil)[:8]) % otpModulus

	return fmt.Sprintf("%0*d", otpDigits, value), nil
}

func encodeOTPMessage(flowID, purpose string, generation uint64, salt []byte) []byte {
	var msg []byte

	appendField := func(b []byte) {
		msg = binary.BigEndian.AppendUint32(msg, uint32(len(b)))
		msg = append(msg, b...)
	}
	appendField([]byte(otpFormatDomain))
	appendField([]byte(flowID))
	appendField([]byte(purpose))

	msg = binary.BigEndian.AppendUint64(msg, generation)

	appendField(salt)

	return msg
}

func isCode(s string) bool {
	if len(s) != otpDigits {
		return false
	}

	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}

	return true
}
