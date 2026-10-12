package emailauth

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/authflow"
	"airlance.org/auth/internal/domain/identity"
)

// ResendDeps are the dependencies of Resend.
type ResendDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
	OTP        port.OTPGenerations
	Bindings   port.BindingSecrets
	Policy     authflow.Policy
	// Registration is who may open an account; the zero value is open.
	Registration identity.RegistrationMode
}

// Resend queues a new code generation of an existing flow.
type Resend struct {
	ResendDeps
}

// NewResend checks the dependencies once, at assembly time.
func NewResend(d ResendDeps) (*Resend, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.OTP == nil || d.Bindings == nil {
		return nil, errors.New("new resend: all dependencies are required")
	}
	if err := d.Policy.Validate(); err != nil {
		return nil, fmt.Errorf("new resend: %w", err)
	}
	return &Resend{d}, nil
}

// ResendCommand is the input of Resend.
type ResendCommand struct {
	FlowID        string
	BindingSecret string
	// ClientIP is the client address behind trusted proxies; the zero value is unknown.
	ClientIP netip.Addr
}

// ResendResult is the output of Resend.
type ResendResult struct {
	Outcome Outcome
	Reason  Reason
	// ExpiresAt is unchanged by resend; ResendAfter is the next allowed resend,
	// also reported when the pause stopped the request.
	ExpiresAt   time.Time
	ResendAfter time.Time
}

// Execute starts a new code generation inside the same flow. A refusal changes
// nothing except that an expired flow is recorded as expired.
func (s *Resend) Execute(ctx context.Context, cmd ResendCommand) (ResendResult, error) {
	id, err := authflow.ParseFlowID(cmd.FlowID)
	if err != nil {
		return ResendResult{Outcome: OutcomeDenied, Reason: ReasonUnknownFlow}, nil
	}
	binding, err := s.Bindings.HashBinding(cmd.BindingSecret)
	if errors.Is(err, port.ErrInvalidBindingSecret) {
		return ResendResult{Outcome: OutcomeDenied, Reason: ReasonBadBinding}, nil
	}
	if err != nil {
		return ResendResult{}, fmt.Errorf("resend: binding: %w", err)
	}

	gen, err := s.OTP.NewGeneration()
	if err != nil {
		return ResendResult{}, fmt.Errorf("resend: %w", err)
	}
	now := s.Clock.Now()

	var result ResendResult
	err = s.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		flow, err := st.Flows.GetForUpdate(ctx, id)
		if errors.Is(err, port.ErrNotFound) {
			result = ResendResult{Outcome: OutcomeDenied, Reason: ReasonUnknownFlow}
			return nil
		}
		if err != nil {
			return fmt.Errorf("load flow: %w", err)
		}

		err = flow.Resend(now, authflow.PurposeLogin, binding, gen.Salt, gen.KeyID, s.Policy)
		if outcome, reason, ok := denial(err); ok {
			if changedFlow(err) {
				if err := st.Flows.Save(ctx, flow); err != nil {
					return fmt.Errorf("store expired flow: %w", err)
				}
			}
			result = ResendResult{Outcome: outcome, Reason: reason, ExpiresAt: flow.ExpiresAt(), ResendAfter: flow.ResendAfter()}
			return nil
		}
		if err != nil {
			return fmt.Errorf("resend flow state: %w", err)
		}

		if lost, err := recognitionLost(ctx, st, flow, now); err != nil {
			return err
		} else if lost {
			result = ResendResult{Outcome: OutcomeDenied, Reason: ReasonRecognitionLost}
			return nil
		}

		allowed, err := st.Limiter.Allow(ctx, port.Spend{
			Kind: port.SpendSend, Email: flow.Email(), Class: flow.QuotaClass(),
			RecognizedClientID: flow.RecognizedClientID(), Binding: binding, IP: cmd.ClientIP, Now: now,
		})
		if err != nil {
			return fmt.Errorf("spend send quota: %w", err)
		}
		if !allowed {
			// The new generation was only built in memory; leaving it unsaved discards it.
			result = ResendResult{Outcome: OutcomeRateLimited, Reason: ReasonQuota}
			return nil
		}

		if err := st.Flows.Save(ctx, flow); err != nil {
			return fmt.Errorf("store flow: %w", err)
		}
		result = ResendResult{Outcome: OutcomeOK, ExpiresAt: flow.ExpiresAt(), ResendAfter: flow.ResendAfter()}
		refusal, err := mayReceiveCode(ctx, st, s.Registration, flow.Email(), now)
		if err != nil {
			return err
		}
		if refusal != "" {
			result.Reason = refusal
			return nil
		}
		if err := st.Outbox.Enqueue(ctx, port.MailJob{
			FlowID: flow.ID(), Generation: flow.Generation(), QuotaClass: flow.QuotaClass(), AvailableAt: now,
		}); err != nil {
			return fmt.Errorf("enqueue mail: %w", err)
		}
		return nil
	})
	if err != nil {
		return ResendResult{}, fmt.Errorf("resend: %w", err)
	}
	return result, nil
}
