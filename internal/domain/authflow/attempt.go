package authflow

import (
	"time"

	"airlance.org/auth/internal/domain/identity"
)

// Attempt is the admission for one code comparison against one generation.
// Reserve spends an attempt before the comparison; Accept or Reject records its result.
type Attempt struct {
	flowID     FlowID
	generation uint64
}

// FlowID returns the flow the attempt belongs to.
func (a Attempt) FlowID() FlowID { return a.flowID }

// Generation returns the code generation the attempt may be compared with.
func (a Attempt) Generation() uint64 { return a.generation }

// Reserve spends one verification attempt for the current generation. The attempt
// stays spent whatever happens next. A reserved last attempt does not lock the
// flow, so it can still complete. A wrong purpose or binding spends nothing.
func (f *Flow) Reserve(now time.Time, purpose Purpose, binding identity.BindingHash, policy Policy) (Attempt, error) {
	if err := f.checkOpen(now); err != nil {
		return Attempt{}, err
	}
	if err := f.checkCaller(purpose, binding); err != nil {
		return Attempt{}, err
	}
	if f.attempts >= policy.MaxAttempts {
		return Attempt{}, ErrAttemptsExhausted
	}
	f.attempts++
	return Attempt{flowID: f.id, generation: f.generation}, nil
}

// Accept records a matching code: the flow becomes consumed and its salt is cleared.
// It fails when the flow was closed, expired or resent after the reservation.
func (f *Flow) Accept(a Attempt, now time.Time) error {
	if err := f.checkResult(a, now); err != nil {
		return err
	}
	f.close(StateConsumed)
	return nil
}

// Reject records a wrong code. Once all attempts are reserved the flow becomes
// locked, which also denies attempts still in flight: the number of comparisons
// never exceeds the policy limit.
func (f *Flow) Reject(a Attempt, now time.Time, policy Policy) error {
	if err := f.checkResult(a, now); err != nil {
		return err
	}
	if f.attempts >= policy.MaxAttempts {
		f.close(StateLocked)
	}
	return nil
}

func (f *Flow) checkResult(a Attempt, now time.Time) error {
	if err := f.checkOpen(now); err != nil {
		return err
	}
	if a.flowID != f.id || a.generation != f.generation {
		return ErrStaleAttempt
	}
	return nil
}
