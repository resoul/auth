package emailauth

import (
	"errors"

	"go.airlance.org/auth/internal/domain/authflow"
)

// Outcome is the externally visible result class of a use case. Transports map
// it to one public response; Reason is only for audit and tests.
type Outcome string

// Outcomes.
const (
	// OutcomeOK means the operation happened.
	OutcomeOK Outcome = "ok"
	// OutcomeDenied is an expected refusal. Every refusal of verify looks the same to clients.
	OutcomeDenied Outcome = "denied"
	// OutcomeRateLimited means a quota or the resend pause stopped the request.
	OutcomeRateLimited Outcome = "rate_limited"
)

// Reason says why a request was refused. It must not reach clients.
type Reason string

// Reasons.
const (
	ReasonUnknownFlow       Reason = "unknown_flow"
	ReasonBadBinding        Reason = "bad_binding"
	ReasonPurpose           Reason = "purpose_mismatch"
	ReasonClosed            Reason = "flow_closed"
	ReasonExpired           Reason = "flow_expired"
	ReasonAttemptsExhausted Reason = "attempts_exhausted"
	ReasonWrongCode         Reason = "wrong_code"
	ReasonStaleAttempt      Reason = "stale_attempt"
	ReasonResendPause       Reason = "resend_pause"
	ReasonQuota             Reason = "quota"
	ReasonRecognitionLost   Reason = "recognition_lost"
	// ReasonNotInvited is a registration the invite-only mode does not allow. A start or resend that
	// carries it still looks like any other to the client; only the mail is not sent.
	ReasonNotInvited Reason = "not_invited"
	// ReasonBlocked is an address whose account an operator blocked. It looks like any other start, as
	// ReasonNotInvited does: only the mail is not sent.
	ReasonBlocked Reason = "blocked"
)

// denial classifies a flow error as an expected refusal. Other errors are technical.
func denial(err error) (Outcome, Reason, bool) {
	switch {
	case errors.Is(err, authflow.ErrClosed):
		return OutcomeDenied, ReasonClosed, true
	case errors.Is(err, authflow.ErrExpired):
		return OutcomeDenied, ReasonExpired, true
	case errors.Is(err, authflow.ErrPurposeMismatch):
		return OutcomeDenied, ReasonPurpose, true
	case errors.Is(err, authflow.ErrBindingMismatch):
		return OutcomeDenied, ReasonBadBinding, true
	case errors.Is(err, authflow.ErrAttemptsExhausted):
		return OutcomeDenied, ReasonAttemptsExhausted, true
	case errors.Is(err, authflow.ErrStaleAttempt):
		return OutcomeDenied, ReasonStaleAttempt, true
	case errors.Is(err, authflow.ErrResendTooSoon):
		return OutcomeRateLimited, ReasonResendPause, true
	}

	return "", "", false
}

// changedFlow reports whether a denial changed the flow and the flow must be
// saved: only expiry does.
func changedFlow(err error) bool { return errors.Is(err, authflow.ErrExpired) }
