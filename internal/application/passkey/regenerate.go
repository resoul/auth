package passkey

import (
	"context"
	"errors"
	"fmt"
	"time"

	"airlance.org/auth/internal/application/port"
	appsession "airlance.org/auth/internal/application/session"
	"airlance.org/auth/internal/domain/identity"
	dpasskey "airlance.org/auth/internal/domain/passkey"
)

// RegenerateRecoveryCodesDeps are the dependencies of RegenerateRecoveryCodes.
type RegenerateRecoveryCodesDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
	Tickets    port.TicketSecrets
	Recovery   port.RecoveryCodes
	PasskeyIDs port.PasskeyIDGenerator
}

// RegenerateRecoveryCodes replaces the recovery codes of the acting user with a fresh set. It
// needs the step-up ticket for regenerate_recovery_codes.
type RegenerateRecoveryCodes struct{ RegenerateRecoveryCodesDeps }

// NewRegenerateRecoveryCodes checks the dependencies once, at assembly time.
func NewRegenerateRecoveryCodes(d RegenerateRecoveryCodesDeps) (*RegenerateRecoveryCodes, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.Tickets == nil || d.Recovery == nil || d.PasskeyIDs == nil {
		return nil, errors.New("new regenerate recovery codes: all dependencies are required")
	}
	return &RegenerateRecoveryCodes{d}, nil
}

// RegenerateCommand is the input of RegenerateRecoveryCodes.
type RegenerateCommand struct {
	Actor        appsession.Actor
	StepUpSecret string
}

// RegenerateResult is the output of RegenerateRecoveryCodes. Codes is set only for OutcomeOK.
type RegenerateResult struct {
	Outcome Outcome
	Reason  Reason
	// Codes are shown once; the store keeps their hashes.
	Codes []string
}

// Execute issues the new set. The old codes stop working at once.
func (u *RegenerateRecoveryCodes) Execute(ctx context.Context, cmd RegenerateCommand) (RegenerateResult, error) {
	now := u.Clock.Now()
	var result RegenerateResult
	err := u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if _, ok, err := appsession.ActiveSession(ctx, st, cmd.Actor, now); err != nil {
			return err
		} else if !ok {
			result = RegenerateResult{Outcome: OutcomeDenied, Reason: ReasonNoSession}
			return nil
		}
		ticket, ok, err := StepUpTicket(ctx, st, u.Tickets, cmd.StepUpSecret, cmd.Actor, dpasskey.OperationRegenerateCodes, now)
		if err != nil {
			return err
		}
		if !ok {
			result = RegenerateResult{Outcome: OutcomeStepUpRequired, Reason: ReasonStepUp}
			return nil
		}
		codes, err := issueRecoveryCodes(ctx, st, u.Recovery, u.PasskeyIDs, cmd.Actor.UserID, now)
		if err != nil {
			return err
		}
		if err := SpendStepUp(ctx, st, ticket, cmd.Actor, dpasskey.OperationRegenerateCodes, now); err != nil {
			return err
		}
		if err := st.Audit.Record(ctx, port.AuditEvent{
			Type: port.AuditRecoveryRenewed, Result: port.AuditSuccess, UserID: cmd.Actor.UserID, SessionID: cmd.Actor.SessionID, At: now,
		}); err != nil {
			return fmt.Errorf("record audit event: %w", err)
		}
		result = RegenerateResult{Outcome: OutcomeOK, Codes: codes}
		return nil
	})
	if err != nil {
		return RegenerateResult{}, fmt.Errorf("regenerate recovery codes: %w", err)
	}
	return result, nil
}

// issueRecoveryCodes makes a fresh set the only valid one and returns it in display form.
func issueRecoveryCodes(ctx context.Context, st port.Stores, codes port.RecoveryCodes, ids port.PasskeyIDGenerator,
	userID identity.UserID, now time.Time) ([]string, error) {
	issued, err := codes.NewRecoveryCodes()
	if err != nil {
		return nil, fmt.Errorf("new recovery codes: %w", err)
	}
	stored := make([]*dpasskey.RecoveryCode, 0, len(issued))
	shown := make([]string, 0, len(issued))
	for _, code := range issued {
		id, err := ids.NewPasskeyID()
		if err != nil {
			return nil, fmt.Errorf("new recovery code id: %w", err)
		}
		c, err := dpasskey.NewRecoveryCode(id, userID, code.Hash, now)
		if err != nil {
			return nil, fmt.Errorf("new recovery code: %w", err)
		}
		stored = append(stored, c)
		shown = append(shown, dpasskey.FormatRecoveryCode(code.Code))
	}
	if err := st.Recovery.Replace(ctx, userID, stored); err != nil {
		return nil, fmt.Errorf("store recovery codes: %w", err)
	}
	return shown, nil
}
