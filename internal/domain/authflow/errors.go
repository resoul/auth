package authflow

import "errors"

// Denials are expected outcomes, not technical failures. A denial may still have
// changed the flow (for example it became expired); callers persist the flow in the same transaction.
var (
	// ErrClosed means the flow is already consumed, locked or expired.
	ErrClosed = errors.New("flow is closed")
	// ErrExpired means the flow lifetime ended; the flow is now expired.
	ErrExpired = errors.New("flow expired")
	// ErrPurposeMismatch means the request names a different purpose.
	ErrPurposeMismatch = errors.New("flow purpose mismatch")
	// ErrBindingMismatch means the request carries a different client binding.
	ErrBindingMismatch = errors.New("flow binding mismatch")
	// ErrAttemptsExhausted means every verification attempt is already reserved.
	ErrAttemptsExhausted = errors.New("flow attempts exhausted")
	// ErrResendTooSoon means the pause before the next resend has not passed.
	ErrResendTooSoon = errors.New("flow resend too soon")
	// ErrStaleAttempt means the code generation changed after the attempt was reserved.
	ErrStaleAttempt = errors.New("flow attempt is stale")
)
