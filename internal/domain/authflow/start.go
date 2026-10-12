package authflow

import (
	"errors"
	"fmt"
	"time"

	"airlance.org/auth/internal/domain/identity"
)

// StartParams are the server-chosen inputs of a new flow.
type StartParams struct {
	ID      FlowID
	Email   identity.Email
	Purpose Purpose
	Binding identity.BindingHash
	// Salt and KeyID belong to generation 1 and come from the OTP adapter.
	Salt  []byte
	KeyID string
	// QuotaClass is chosen by the server; RecognizedClientID is required exactly for QuotaRecognized.
	QuotaClass         QuotaClass
	RecognizedClientID identity.RecognizedClientID
	// UserID is required exactly for PurposeChangeEmail: the account whose address changes.
	UserID identity.UserID
}

// Start creates a pending flow with generation 1. Expiry and the resend pause run from now.
func Start(p StartParams, now time.Time, policy Policy) (*Flow, error) {
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("start flow: %w", err)
	}
	if now.IsZero() {
		return nil, errors.New("start flow: time is required")
	}
	f := &Flow{
		id: p.ID, email: p.Email, purpose: p.Purpose, generation: 1,
		salt: append([]byte(nil), p.Salt...), keyID: p.KeyID, bindingHash: p.Binding,
		state: StatePending, createdAt: now, expiresAt: now.Add(policy.TTL),
		resendAfter: now.Add(policy.ResendPause),
		quotaClass:  p.QuotaClass, recognizedClientID: p.RecognizedClientID, userID: p.UserID,
	}
	if err := f.validate(); err != nil {
		return nil, fmt.Errorf("start flow: %w", err)
	}
	return f, nil
}
