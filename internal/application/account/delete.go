package account

import (
	"context"
	"errors"
	"fmt"

	"airlance.org/auth/internal/application/passkey"
	"airlance.org/auth/internal/application/port"
	appsession "airlance.org/auth/internal/application/session"
	dpasskey "airlance.org/auth/internal/domain/passkey"
)

// DeleteAccountDeps are the dependencies of DeleteAccount.
type DeleteAccountDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
	Tickets    port.TicketSecrets
}

// DeleteAccount permanently removes the authenticated account after a fresh passkey proof.
type DeleteAccount struct{ DeleteAccountDeps }

// NewDeleteAccount checks dependencies at assembly time.
func NewDeleteAccount(d DeleteAccountDeps) (*DeleteAccount, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.Tickets == nil {
		return nil, errors.New("new delete account: all dependencies are required")
	}
	return &DeleteAccount{d}, nil
}

// DeleteAccountCommand carries an authenticated actor and the operation's step-up secret.
type DeleteAccountCommand struct {
	Actor        appsession.Actor
	StepUpSecret string
}

// DeleteAccountResult reports success or an expected refusal.
type DeleteAccountResult struct {
	Outcome Outcome
	Reason  Reason
}

// Execute spends the proof, records the audit and deletes the account in one transaction.
func (u *DeleteAccount) Execute(ctx context.Context, cmd DeleteAccountCommand) (DeleteAccountResult, error) {
	now := u.Clock.Now()
	var result DeleteAccountResult
	err := u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		_, ok, err := appsession.ActiveSession(ctx, st, cmd.Actor, now)
		if err != nil {
			return err
		}
		if !ok {
			result = DeleteAccountResult{Outcome: OutcomeDenied, Reason: ReasonNoSession}
			return nil
		}
		ticket, ok, err := passkey.StepUpTicket(ctx, st, u.Tickets, cmd.StepUpSecret, cmd.Actor, dpasskey.OperationDeleteAccount, now)
		if err != nil {
			return err
		}
		if !ok {
			result = DeleteAccountResult{Outcome: OutcomeStepUpRequired, Reason: ReasonStepUp}
			return nil
		}
		if err := passkey.SpendStepUp(ctx, st, ticket, cmd.Actor, dpasskey.OperationDeleteAccount, now); err != nil {
			return err
		}
		if err := st.Audit.Record(ctx, port.AuditEvent{Type: port.AuditAccountDeleted, Result: port.AuditSuccess, UserID: cmd.Actor.UserID, SessionID: cmd.Actor.SessionID, At: now}); err != nil {
			return err
		}
		if err := st.Users.Delete(ctx, cmd.Actor.UserID); err != nil {
			return err
		}
		result = DeleteAccountResult{Outcome: OutcomeOK}
		return nil
	})
	if err != nil {
		return DeleteAccountResult{}, fmt.Errorf("delete account: %w", err)
	}
	return result, nil
}
