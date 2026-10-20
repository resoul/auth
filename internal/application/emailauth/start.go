package emailauth

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/authflow"
	"go.airlance.org/auth/internal/domain/identity"
)

// StartDeps are the dependencies of Start.
type StartDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
	FlowIDs    port.FlowIDGenerator
	OTP        port.OTPGenerations
	Bindings   port.BindingSecrets
	Policy     authflow.Policy
	// Registration is who may open an account; the zero value is open.
	Registration identity.RegistrationMode
}

// Start begins an email login flow and queues its first code.
type Start struct {
	StartDeps
}

// NewStart checks the dependencies once, at assembly time.
func NewStart(d StartDeps) (*Start, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.FlowIDs == nil || d.OTP == nil || d.Bindings == nil {
		return nil, errors.New("new start: all dependencies are required")
	}

	if err := d.Policy.Validate(); err != nil {
		return nil, fmt.Errorf("new start: %w", err)
	}

	return &Start{d}, nil
}

// StartCommand is the input of Start.
type StartCommand struct {
	Email string
	// BindingSecret is the client's existing binding secret; empty for a new client.
	BindingSecret string
	// ClientIP is the client address behind trusted proxies; the zero value is unknown.
	ClientIP netip.Addr
}

// StartResult is the output of Start. It does not depend on whether the email has a User.
type StartResult struct {
	Outcome     Outcome
	Reason      Reason
	FlowID      authflow.FlowID
	ExpiresAt   time.Time
	ResendAfter time.Time
	// NewBindingSecret is set only when the server issued a binding in this call.
	NewBindingSecret string
}

// Execute starts a flow. Invalid input returns an error and writes nothing; an
// exhausted quota is OutcomeRateLimited and writes nothing.
func (s *Start) Execute(ctx context.Context, cmd StartCommand) (StartResult, error) {
	email, err := identity.ParseEmail(cmd.Email)
	if err != nil {
		return StartResult{}, fmt.Errorf("start: %w", err)
	}

	var (
		secret  string
		binding identity.BindingHash
	)
	if cmd.BindingSecret == "" {
		secret, binding, err = s.Bindings.NewBinding()
	} else {
		binding, err = s.Bindings.HashBinding(cmd.BindingSecret)
	}

	if err != nil {
		return StartResult{}, fmt.Errorf("start: binding: %w", err)
	}

	issued := secret

	flowID, err := s.FlowIDs.NewFlowID()
	if err != nil {
		return StartResult{}, fmt.Errorf("start: %w", err)
	}

	gen, err := s.OTP.NewGeneration()
	if err != nil {
		return StartResult{}, fmt.Errorf("start: %w", err)
	}

	now := s.Clock.Now()

	var result StartResult

	err = s.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		// The server picks the quota class and keeps it for the whole flow. Only a client
		// that presented its binding can be recognized; a binding issued just now cannot.
		class := authflow.QuotaUnknown

		var recognizedID identity.RecognizedClientID

		if cmd.BindingSecret != "" {
			rc, err := st.Recognized.FindActive(ctx, email, binding, now)
			switch {
			case err == nil:
				class, recognizedID = authflow.QuotaRecognized, rc.ID()
			case !errors.Is(err, port.ErrNotFound):
				return fmt.Errorf("look up recognized client: %w", err)
			}
		}

		allowed, err := st.Limiter.Allow(ctx, port.Spend{
			Kind: port.SpendSend, Email: email, Class: class, RecognizedClientID: recognizedID, Binding: binding,
			IP: cmd.ClientIP, Now: now,
		})
		if err != nil {
			return fmt.Errorf("spend send quota: %w", err)
		}

		if !allowed {
			result = StartResult{Outcome: OutcomeRateLimited, Reason: ReasonQuota}
			return nil
		}

		flow, err := authflow.Start(authflow.StartParams{
			ID: flowID, Email: email, Purpose: authflow.PurposeLogin, Binding: binding,
			Salt: gen.Salt, KeyID: gen.KeyID, QuotaClass: class, RecognizedClientID: recognizedID,
		}, now, s.Policy)
		if err != nil {
			return fmt.Errorf("create flow state: %w", err)
		}

		if err := st.Flows.Create(ctx, flow); err != nil {
			return fmt.Errorf("store flow: %w", err)
		}

		result = StartResult{
			Outcome: OutcomeOK, FlowID: flow.ID(), ExpiresAt: flow.ExpiresAt(),
			ResendAfter: flow.ResendAfter(), NewBindingSecret: issued,
		}
		// The flow and the quota are the same for everyone; only an address that may register or sign in gets mail.
		refusal, err := mayReceiveCode(ctx, st, s.Registration, email, now)
		if err != nil {
			return err
		}

		if refusal != "" {
			result.Reason = refusal
			return nil
		}

		if err := st.Outbox.Enqueue(ctx, port.MailJob{
			FlowID: flow.ID(), Generation: flow.Generation(), QuotaClass: class, AvailableAt: now,
		}); err != nil {
			return fmt.Errorf("enqueue mail: %w", err)
		}

		return nil
	})
	if err != nil {
		return StartResult{}, fmt.Errorf("start: %w", err)
	}

	return result, nil
}
