package deviceauth

import (
	"errors"

	"go.airlance.org/auth/internal/domain/deviceauth"
)

// Outcome is the externally visible result class of a use case.
type Outcome string

// Outcomes.
const (
	// OutcomeOK means the operation happened.
	OutcomeOK Outcome = "ok"
	// OutcomeDenied is an expected refusal. Every refusal of the new device looks the same to clients.
	OutcomeDenied Outcome = "denied"
	// OutcomeRateLimited means the quota of device requests stopped the request.
	OutcomeRateLimited Outcome = "rate_limited"
	// OutcomeStepUpRequired means the approval needs a fresh passkey proof the request did not carry.
	OutcomeStepUpRequired Outcome = "step_up_required"
	// OutcomeNotFound means the approving device has no live request of that identifier.
	OutcomeNotFound Outcome = "not_found"
)

// Reason says why a request was refused. It is for audit and tests and must not reach clients.
type Reason string

// Reasons.
const (
	ReasonUnknownRequest    Reason = "unknown_request"
	ReasonBadSecret         Reason = "bad_secret"
	ReasonBadBinding        Reason = "bad_binding"
	ReasonExpired           Reason = "expired"
	ReasonNotPending        Reason = "not_pending"
	ReasonNotApproved       Reason = "not_approved"
	ReasonWrongCode         Reason = "wrong_code"
	ReasonAttemptsExhausted Reason = "attempts_exhausted"
	ReasonQuota             Reason = "quota"
	ReasonNoSession         Reason = "no_session"
	ReasonStepUp            Reason = "step_up_required"
	ReasonApproverGone      Reason = "approver_gone"
	ReasonBlocked           Reason = "blocked"
)

// ErrInvalidName reports a device name that cannot be kept; the transport answers invalid_request.
var ErrInvalidName = errors.New("invalid device name")

// denial classifies an error of the request state as an expected refusal.
func denial(err error) (Reason, bool) {
	switch {
	case errors.Is(err, deviceauth.ErrExpired):
		return ReasonExpired, true
	case errors.Is(err, deviceauth.ErrNotPending):
		return ReasonNotPending, true
	case errors.Is(err, deviceauth.ErrNotApproved):
		return ReasonNotApproved, true
	case errors.Is(err, deviceauth.ErrWrongCode):
		return ReasonWrongCode, true
	case errors.Is(err, deviceauth.ErrAttemptsExhausted):
		return ReasonAttemptsExhausted, true
	case errors.Is(err, deviceauth.ErrMismatch):
		return ReasonBadSecret, true
	}

	return "", false
}

// changed reports whether a refusal changed the request and it must be saved: a wrong code spends an attempt.
func changed(err error) bool {
	return errors.Is(err, deviceauth.ErrWrongCode) || errors.Is(err, deviceauth.ErrAttemptsExhausted)
}
