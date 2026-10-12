package deviceauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"airlance.org/auth/internal/application/passkey"
	"airlance.org/auth/internal/application/port"
	appsession "airlance.org/auth/internal/application/session"
	ddevice "airlance.org/auth/internal/domain/deviceauth"
	dpasskey "airlance.org/auth/internal/domain/passkey"
)

// ApproveDeps are the dependencies of Inspect, Approve and Deny.
type ApproveDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
	Tickets    port.TicketSecrets
}

// Approver is what a signed-in device may do with a request.
type Approver struct{ ApproveDeps }

// NewApprover checks the dependencies once, at assembly time.
func NewApprover(d ApproveDeps) (*Approver, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.Tickets == nil {
		return nil, errors.New("new device approver: all dependencies are required")
	}
	return &Approver{d}, nil
}

// RequestView is what the approving device shows before the person decides.
type RequestView struct {
	DeviceName string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// InspectResult is the output of Inspect.
type InspectResult struct {
	Outcome Outcome
	Reason  Reason
	View    RequestView
}

// Inspect shows a live pending request to a signed-in user. The pairing code is not part of it: it is on the
// new device, and the person must read it there.
func (u *Approver) Inspect(ctx context.Context, actor appsession.Actor, requestID string) (InspectResult, error) {
	id, err := ddevice.ParseRequestID(requestID)
	if err != nil {
		return InspectResult{Outcome: OutcomeNotFound, Reason: ReasonUnknownRequest}, nil
	}
	now := u.Clock.Now()
	result := InspectResult{Outcome: OutcomeNotFound, Reason: ReasonUnknownRequest}
	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if _, ok, err := appsession.ActiveSession(ctx, st, actor, now); err != nil {
			return err
		} else if !ok {
			result = InspectResult{Outcome: OutcomeDenied, Reason: ReasonNoSession}
			return nil
		}
		req, err := st.Devices.Get(ctx, id)
		if errors.Is(err, port.ErrNotFound) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("load device request: %w", err)
		}
		if req.State() != ddevice.StatePending || !req.Live(now) {
			result.Reason = ReasonNotPending
			return nil
		}
		result = InspectResult{Outcome: OutcomeOK, View: RequestView{DeviceName: req.DeviceName(), CreatedAt: req.CreatedAt(), ExpiresAt: req.ExpiresAt()}}
		return nil
	})
	if err != nil {
		return InspectResult{}, fmt.Errorf("inspect device request: %w", err)
	}
	return result, nil
}

// ApproveCommand is the input of Approve. Actor comes from the Authenticator.
type ApproveCommand struct {
	Actor     appsession.Actor
	RequestID string
	// PairingCode is what the person typed from the screen of the new device.
	PairingCode string
	// StepUpSecret is the step-up token for approve_device.
	StepUpSecret string
}

// Result is the output of Approve and Deny.
type Result struct {
	Outcome Outcome
	Reason  Reason
}

// Approve lets the new device sign in as the user of the approving session. It needs a passkey proof made now
// and the pairing code; a refusal spends no proof, and wrong codes spend the attempts of the request.
func (u *Approver) Approve(ctx context.Context, cmd ApproveCommand) (Result, error) {
	id, err := ddevice.ParseRequestID(cmd.RequestID)
	if err != nil {
		return Result{Outcome: OutcomeNotFound, Reason: ReasonUnknownRequest}, nil
	}
	now := u.Clock.Now()
	var result Result
	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if _, ok, err := appsession.ActiveSession(ctx, st, cmd.Actor, now); err != nil {
			return err
		} else if !ok {
			result = Result{Outcome: OutcomeDenied, Reason: ReasonNoSession}
			return nil
		}
		ticket, ok, err := passkey.StepUpTicket(ctx, st, u.Tickets, cmd.StepUpSecret, cmd.Actor, dpasskey.OperationApproveDevice, now)
		if err != nil {
			return err
		}
		if !ok {
			result = Result{Outcome: OutcomeStepUpRequired, Reason: ReasonStepUp}
			return nil
		}
		req, err := st.Devices.GetForUpdate(ctx, id)
		if errors.Is(err, port.ErrNotFound) {
			result = Result{Outcome: OutcomeNotFound, Reason: ReasonUnknownRequest}
			return nil
		}
		if err != nil {
			return fmt.Errorf("load device request: %w", err)
		}
		if err := req.Approve(now, cmd.Actor.UserID, cmd.Actor.SessionID, cmd.PairingCode); err != nil {
			reason, ok := denial(err)
			if !ok {
				return fmt.Errorf("approve device request: %w", err)
			}
			result = Result{Outcome: OutcomeDenied, Reason: reason}
			if changed(err) {
				// The spent attempt, and the death of the request on the last one, are committed.
				if err := st.Devices.Save(ctx, req); err != nil {
					return fmt.Errorf("store device request: %w", err)
				}
			}
			if reason == ReasonAttemptsExhausted {
				// Someone guessed the pairing code of a live request: the death of the request is the trace.
				if err := st.Audit.Record(ctx, port.AuditEvent{
					Type: port.AuditDeviceDenied, Result: port.AuditDenied, UserID: cmd.Actor.UserID, SessionID: cmd.Actor.SessionID, At: now,
					Fields: map[string]string{"reason": string(reason)},
				}); err != nil {
					return fmt.Errorf("record audit event: %w", err)
				}
			}
			return nil
		}
		if err := st.Devices.Save(ctx, req); err != nil {
			return fmt.Errorf("store device request: %w", err)
		}
		if err := passkey.SpendStepUp(ctx, st, ticket, cmd.Actor, dpasskey.OperationApproveDevice, now); err != nil {
			return err
		}
		if err := st.Audit.Record(ctx, port.AuditEvent{
			Type: port.AuditDeviceApproved, Result: port.AuditSuccess, UserID: cmd.Actor.UserID, SessionID: cmd.Actor.SessionID, At: now,
		}); err != nil {
			return fmt.Errorf("record audit event: %w", err)
		}
		result = Result{Outcome: OutcomeOK}
		return nil
	})
	if err != nil {
		return Result{}, fmt.Errorf("approve device request: %w", err)
	}
	return result, nil
}

// Deny refuses a pending request. It needs a session but no passkey proof: refusing opens nothing.
func (u *Approver) Deny(ctx context.Context, actor appsession.Actor, requestID string) (Result, error) {
	id, err := ddevice.ParseRequestID(requestID)
	if err != nil {
		return Result{Outcome: OutcomeNotFound, Reason: ReasonUnknownRequest}, nil
	}
	now := u.Clock.Now()
	var result Result
	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if _, ok, err := appsession.ActiveSession(ctx, st, actor, now); err != nil {
			return err
		} else if !ok {
			result = Result{Outcome: OutcomeDenied, Reason: ReasonNoSession}
			return nil
		}
		req, err := st.Devices.GetForUpdate(ctx, id)
		if errors.Is(err, port.ErrNotFound) {
			result = Result{Outcome: OutcomeNotFound, Reason: ReasonUnknownRequest}
			return nil
		}
		if err != nil {
			return fmt.Errorf("load device request: %w", err)
		}
		if err := req.Deny(now); err != nil {
			reason, ok := denial(err)
			if !ok {
				return fmt.Errorf("deny device request: %w", err)
			}
			result = Result{Outcome: OutcomeNotFound, Reason: reason}
			return nil
		}
		if err := st.Devices.Save(ctx, req); err != nil {
			return fmt.Errorf("store device request: %w", err)
		}
		if err := st.Audit.Record(ctx, port.AuditEvent{
			Type: port.AuditDeviceDenied, Result: port.AuditSuccess, UserID: actor.UserID, SessionID: actor.SessionID, At: now,
		}); err != nil {
			return fmt.Errorf("record audit event: %w", err)
		}
		result = Result{Outcome: OutcomeOK}
		return nil
	})
	if err != nil {
		return Result{}, fmt.Errorf("deny device request: %w", err)
	}
	return result, nil
}
