package account

import (
	"errors"

	"airlance.org/auth/internal/domain/authflow"
)

// Outcome is the externally visible result class of a use case.
type Outcome string

// Outcomes.
const (
	// OutcomeOK means the operation happened.
	OutcomeOK Outcome = "ok"
	// OutcomeDenied is an expected refusal. Every refusal of a proof looks the same to clients.
	OutcomeDenied Outcome = "denied"
	// OutcomeRateLimited means a quota or an attempt budget stopped the request.
	OutcomeRateLimited Outcome = "rate_limited"
	// OutcomeStepUpRequired means the operation needs a fresh strong proof the request did not carry.
	OutcomeStepUpRequired Outcome = "step_up_required"
	// OutcomeConflict means the new address belongs to another account.
	OutcomeConflict Outcome = "conflict"
	// OutcomeInvalid means the request asks for no change: the address is the account's own.
	OutcomeInvalid Outcome = "invalid"
)

// Reason says why a request was refused. It is for audit and tests and must not reach clients.
type Reason string

// Reasons.
const (
	ReasonNoSession         Reason = "no_session"
	ReasonStepUp            Reason = "step_up_required"
	ReasonSameEmail         Reason = "same_email"
	ReasonQuota             Reason = "quota"
	ReasonUnknownFlow       Reason = "unknown_flow"
	ReasonBadBinding        Reason = "bad_binding"
	ReasonClosed            Reason = "flow_closed"
	ReasonExpired           Reason = "flow_expired"
	ReasonAttemptsExhausted Reason = "attempts_exhausted"
	ReasonWrongCode         Reason = "wrong_code"
	ReasonStaleAttempt      Reason = "stale_attempt"
	ReasonEmailTaken        Reason = "email_taken"
)

// denial classifies a flow error as an expected refusal. Other errors are technical.
func denial(err error) (Reason, bool) {
	switch {
	case errors.Is(err, authflow.ErrClosed):
		return ReasonClosed, true
	case errors.Is(err, authflow.ErrExpired):
		return ReasonExpired, true
	case errors.Is(err, authflow.ErrPurposeMismatch):
		return ReasonUnknownFlow, true
	case errors.Is(err, authflow.ErrBindingMismatch):
		return ReasonBadBinding, true
	case errors.Is(err, authflow.ErrAttemptsExhausted):
		return ReasonAttemptsExhausted, true
	case errors.Is(err, authflow.ErrStaleAttempt):
		return ReasonStaleAttempt, true
	}
	return "", false
}

// changedFlow reports whether a denial changed the flow and the flow must be saved: only expiry does.
func changedFlow(err error) bool { return errors.Is(err, authflow.ErrExpired) }
