package deviceauth

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"go.airlance.org/auth/internal/application/port"
	ddevice "go.airlance.org/auth/internal/domain/deviceauth"
	"go.airlance.org/auth/internal/domain/identity"
	dsession "go.airlance.org/auth/internal/domain/session"
)

// Authentication methods of a session opened by a device sign-in: the passkey was proven on the approving device.
var amrDevice = []string{"qr", "passkey"}

// StartDeps are the dependencies of Start.
type StartDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
	Secrets    port.DeviceSecrets
	// Tickets issues the poll secret the new device keeps.
	Tickets  port.TicketSecrets
	Bindings port.BindingSecrets
}

// Start makes a request on behalf of a device that has no session.
type Start struct{ StartDeps }

// NewStart checks the dependencies once, at assembly time.
func NewStart(d StartDeps) (*Start, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.Secrets == nil || d.Tickets == nil || d.Bindings == nil {
		return nil, errors.New("new device start: all dependencies are required")
	}

	return &Start{d}, nil
}

// StartCommand is the input of Start.
type StartCommand struct {
	// DeviceName labels the new device on the approving one; it may be empty.
	DeviceName string
	// BindingSecret is the client binding; empty makes the server issue one.
	BindingSecret string
	// ClientIP is the client address behind trusted proxies; the zero value is unknown.
	ClientIP netip.Addr
}

// StartResult is the output of Start. Everything but Outcome and Reason is set only for OutcomeOK.
type StartResult struct {
	Outcome Outcome
	Reason  Reason
	// RequestID is what the QR code carries.
	RequestID ddevice.RequestID
	// PollSecret proves the new device owns the request; it exists only here, the store keeps its hash.
	PollSecret string
	// PairingCode is shown on the new device and typed on the approving one.
	PairingCode string
	ExpiresAt   time.Time
	// NewBindingSecret is set when the server issued the binding: the client keeps it.
	NewBindingSecret string
}

// Execute writes the request. An exhausted quota writes nothing.
func (u *Start) Execute(ctx context.Context, cmd StartCommand) (StartResult, error) {
	if !dsession.ValidDeviceName(cmd.DeviceName) {
		return StartResult{}, fmt.Errorf("start device sign-in: %w", ErrInvalidName)
	}

	var (
		bindingSecret string
		binding       identity.BindingHash
		err           error
	)
	if cmd.BindingSecret == "" {
		bindingSecret, binding, err = u.Bindings.NewBinding()
	} else {
		binding, err = u.Bindings.HashBinding(cmd.BindingSecret)
	}

	if err != nil {
		return StartResult{}, fmt.Errorf("start device sign-in: binding: %w", err)
	}

	id, err := u.Secrets.NewRequestID()
	if err != nil {
		return StartResult{}, fmt.Errorf("start device sign-in: %w", err)
	}

	code, err := u.Secrets.NewPairingCode()
	if err != nil {
		return StartResult{}, fmt.Errorf("start device sign-in: %w", err)
	}

	poll, pollHash, err := u.Tickets.NewTicketSecret()
	if err != nil {
		return StartResult{}, fmt.Errorf("start device sign-in: %w", err)
	}

	now := u.Clock.Now()

	req, err := ddevice.New(ddevice.NewParams{ID: id, PollHash: pollHash, Binding: binding, DeviceName: cmd.DeviceName, PairingCode: code}, now)
	if err != nil {
		return StartResult{}, fmt.Errorf("start device sign-in: %w", err)
	}

	result := StartResult{
		Outcome: OutcomeOK, RequestID: id, PollSecret: poll, PairingCode: code, ExpiresAt: req.ExpiresAt(), NewBindingSecret: bindingSecret,
	}

	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		allowed, err := st.Limiter.Allow(ctx, port.Spend{Kind: port.SpendDevice, IP: cmd.ClientIP, Now: now})
		if err != nil {
			return fmt.Errorf("spend device quota: %w", err)
		}

		if !allowed {
			result = StartResult{Outcome: OutcomeRateLimited, Reason: ReasonQuota}
			return nil
		}

		return st.Devices.Create(ctx, req)
	})
	if err != nil {
		return StartResult{}, fmt.Errorf("start device sign-in: %w", err)
	}

	return result, nil
}
