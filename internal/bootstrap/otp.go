package bootstrap

import (
	"fmt"

	"airlance.org/auth/internal/adapter/crypto"
	"airlance.org/auth/internal/config"
)

// newOTP builds the OTP provider from the keyring. It returns nil when the otp_hmac
// purpose is not configured; a configured purpose must load completely.
func newOTP(ring *config.Keyring) (*crypto.OTP, error) {
	if ring == nil || ring.OTPHMAC == nil {
		return nil, nil
	}
	files := make(map[string]string, len(ring.OTPHMAC.Keys))
	for kid, ref := range ring.OTPHMAC.Keys {
		files[kid] = ref.KeyFile
	}
	keyring, err := crypto.LoadOTPKeyring(ring.OTPHMAC.ActiveKID, files)
	if err != nil {
		return nil, fmt.Errorf("load otp keyring: %w", err)
	}
	otp, err := crypto.NewOTP(keyring, nil)
	if err != nil {
		return nil, fmt.Errorf("create otp: %w", err)
	}
	return otp, nil
}
