package deviceauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"airlance.org/auth/internal/application/port"
	ddevice "airlance.org/auth/internal/domain/deviceauth"
	"airlance.org/auth/internal/domain/identity"
	dpasskey "airlance.org/auth/internal/domain/passkey"
)

// StatusDeps are the dependencies of Status.
type StatusDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
	Tickets    port.TicketSecrets
	Bindings   port.BindingSecrets
}

// Status tells the new device how its request stands.
type Status struct{ StatusDeps }

// NewStatus checks the dependencies once, at assembly time.
func NewStatus(d StatusDeps) (*Status, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.Tickets == nil || d.Bindings == nil {
		return nil, errors.New("new device status: all dependencies are required")
	}
	return &Status{d}, nil
}

// State is what the new device is told. Expiry is a state here: the device only needs to know it must start again.
type State string

// States a status reports.
const (
	StatePending  State = "pending"
	StateApproved State = "approved"
	StateDenied   State = "denied"
	StateRedeemed State = "redeemed"
	StateExpired  State = "expired"
)

// StatusCommand is the input of Status.
type StatusCommand struct {
	RequestID     string
	PollSecret    string
	BindingSecret string
}

// StatusResult is the output of Status.
type StatusResult struct {
	Outcome Outcome
	Reason  Reason
	State   State
}

// proof parses what proves the new device owns a request; a malformed value is a refusal.
func proof(tickets port.TicketSecrets, bindings port.BindingSecrets, requestID, pollSecret, bindingSecret string) (
	id ddevice.RequestID, poll dpasskey.SecretHash, binding identity.BindingHash, reason Reason, err error) {
	if id, err = ddevice.ParseRequestID(requestID); err != nil {
		return id, poll, binding, ReasonUnknownRequest, nil
	}
	if poll, err = tickets.HashTicketSecret(pollSecret); errors.Is(err, port.ErrInvalidTicketSecret) {
		return id, poll, binding, ReasonBadSecret, nil
	} else if err != nil {
		return id, poll, binding, "", fmt.Errorf("poll secret: %w", err)
	}
	if binding, err = bindings.HashBinding(bindingSecret); errors.Is(err, port.ErrInvalidBindingSecret) {
		return id, poll, binding, ReasonBadBinding, nil
	} else if err != nil {
		return id, poll, binding, "", fmt.Errorf("binding: %w", err)
	}
	return id, poll, binding, "", nil
}

// Execute reports the state. Nothing is changed. An unknown request, a wrong secret and a wrong binding are
// the same refusal, so the poll cannot be used to find out which requests exist.
func (u *Status) Execute(ctx context.Context, cmd StatusCommand) (StatusResult, error) {
	id, poll, binding, reason, err := proof(u.Tickets, u.Bindings, cmd.RequestID, cmd.PollSecret, cmd.BindingSecret)
	if err != nil {
		return StatusResult{}, fmt.Errorf("device status: %w", err)
	}
	if reason != "" {
		return StatusResult{Outcome: OutcomeDenied, Reason: reason}, nil
	}
	now := u.Clock.Now()
	result := StatusResult{Outcome: OutcomeDenied, Reason: ReasonUnknownRequest}
	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		req, err := st.Devices.Get(ctx, id)
		if errors.Is(err, port.ErrNotFound) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("load device request: %w", err)
		}
		if !req.Matches(poll, binding) {
			result.Reason = ReasonBadSecret
			return nil
		}
		result = StatusResult{Outcome: OutcomeOK, State: stateOf(req, now)}
		return nil
	})
	if err != nil {
		return StatusResult{}, fmt.Errorf("device status: %w", err)
	}
	return result, nil
}

func stateOf(req *ddevice.Request, now time.Time) State {
	switch req.State() {
	case ddevice.StateDenied:
		return StateDenied
	case ddevice.StateRedeemed:
		return StateRedeemed
	}
	if !req.Live(now) {
		return StateExpired
	}
	if req.State() == ddevice.StateApproved {
		return StateApproved
	}
	return StatePending
}
