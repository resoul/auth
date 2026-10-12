package authflow

import (
	"errors"
	"fmt"
	"time"

	"airlance.org/auth/internal/domain/identity"
)

// Resend starts a new code generation inside the same flow. It neither extends
// the lifetime nor resets attempts. On a denial the previous generation stays valid.
func (f *Flow) Resend(now time.Time, purpose Purpose, binding identity.BindingHash, salt []byte, keyID string, policy Policy) error {
	if err := f.checkOpen(now); err != nil {
		return err
	}
	if err := f.checkCaller(purpose, binding); err != nil {
		return err
	}
	if now.Before(f.resendAfter) {
		return ErrResendTooSoon
	}
	if len(salt) != SaltLength || keyID == "" {
		return errors.New("resend flow: salt and key id are required")
	}
	if err := policy.Validate(); err != nil {
		return fmt.Errorf("resend flow: %w", err)
	}
	f.generation++
	f.salt = append([]byte(nil), salt...)
	f.keyID = keyID
	f.resendAfter = now.Add(policy.ResendPause)
	return nil
}
