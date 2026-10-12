package admin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/operator"
	"airlance.org/auth/internal/domain/passkey"
)

// Outcome is the externally visible result class of a use case.
type Outcome string

// Outcomes.
const (
	// OutcomeOK means the operation happened.
	OutcomeOK Outcome = "ok"
	// OutcomeDenied is an expected refusal of a sign-in or enrollment. Every refusal looks the same to clients.
	OutcomeDenied Outcome = "denied"
	// OutcomeRateLimited means the quota of the admin listener stopped the request.
	OutcomeRateLimited Outcome = "rate_limited"
	// OutcomeUnauthenticated means the session is missing, ended or belongs to a disabled operator.
	OutcomeUnauthenticated Outcome = "unauthenticated"
	// OutcomeNotFound means there is no such object.
	OutcomeNotFound Outcome = "not_found"
	// OutcomeConflict means the request is well formed but would break a rule.
	OutcomeConflict Outcome = "conflict"
	// OutcomeReauthRequired means the operation needs a sign-in newer than the session has.
	OutcomeReauthRequired Outcome = "reauth_required"
)

// Reason says why a request was refused. It is for audit and tests and must not reach clients.
type Reason string

// Reasons.
const (
	ReasonBadCode         Reason = "bad_code"
	ReasonBadChallenge    Reason = "bad_challenge"
	ReasonCeremonyFailed  Reason = "ceremony_failed"
	ReasonCloneSuspected  Reason = "clone_suspected"
	ReasonUnknownKey      Reason = "unknown_key"
	ReasonOperatorOff     Reason = "operator_disabled"
	ReasonTooManyKeys     Reason = "too_many_keys"
	ReasonQuota           Reason = "quota"
	ReasonNoSession       Reason = "no_session"
	ReasonConfirmMismatch Reason = "confirm_mismatch"
	ReasonAlreadyUser     Reason = "already_registered"
)

// ErrInvalidInput reports a request the operator got wrong: a name, a filter or a lifetime out of range.
// The transport answers it with invalid_request.
var ErrInvalidInput = errors.New("invalid admin input")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidInput, fmt.Sprintf(format, args...))
}

// Actor is a signed-in operator, as Authenticate returns it. It is only a name: each operation
// checks the session again.
type Actor struct {
	OperatorID operator.ID
	SessionID  passkey.ID
}

// session loads and checks the session of an actor inside the caller's transaction. ok is false when
// the session ended or its operator is gone or disabled.
func (a Actor) session(ctx context.Context, st port.Stores, now time.Time) (*operator.Session, bool, error) {
	if a.OperatorID.IsZero() || a.SessionID.IsZero() {
		return nil, false, nil
	}
	sess, err := st.OperatorSessions.GetForUpdate(ctx, a.SessionID)
	if errors.Is(err, port.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("load operator session: %w", err)
	}
	if sess.OperatorID() != a.OperatorID || !sess.Active(now) {
		return nil, false, nil
	}
	op, err := st.Operators.Get(ctx, a.OperatorID)
	if errors.Is(err, port.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("load operator: %w", err)
	}
	if op.Disabled() {
		return nil, false, nil
	}
	return sess, true, nil
}

// authorize is the check every operation starts with. It returns the outcome to answer with when the
// actor may not act: unauthenticated, or reauth_required when fresh is set and the sign-in is old.
func (a Actor) authorize(ctx context.Context, st port.Stores, now time.Time, fresh bool) (Outcome, error) {
	sess, ok, err := a.session(ctx, st, now)
	if err != nil {
		return "", err
	}
	switch {
	case !ok:
		return OutcomeUnauthenticated, nil
	case fresh && !sess.Fresh(now):
		return OutcomeReauthRequired, nil
	}
	return OutcomeOK, nil
}

// act records an administrative act of the actor on a user, in the caller's transaction.
func act(ctx context.Context, st port.Stores, now time.Time, a Actor, userID userRef, operation string) error {
	return st.Audit.Record(ctx, port.AuditEvent{
		Type: port.AuditAdminAction, Result: port.AuditSuccess, UserID: userID.id, OperatorID: a.OperatorID, At: now,
		Fields: map[string]string{"operation": operation},
	})
}
