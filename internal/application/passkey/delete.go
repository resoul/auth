package passkey

import (
	"context"
	"errors"
	"fmt"

	"go.airlance.org/auth/internal/application/port"
	appsession "go.airlance.org/auth/internal/application/session"
	dpasskey "go.airlance.org/auth/internal/domain/passkey"
)

// DeleteCredentialDeps are the dependencies of DeleteCredential.
type DeleteCredentialDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
	Tickets    port.TicketSecrets
}

// DeleteCredential removes a passkey of the acting user. It needs the step-up ticket for
// delete_passkey, and the last passkey cannot be removed: a session needs one.
type DeleteCredential struct{ DeleteCredentialDeps }

// NewDeleteCredential checks the dependencies once, at assembly time.
func NewDeleteCredential(d DeleteCredentialDeps) (*DeleteCredential, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.Tickets == nil {
		return nil, errors.New("new delete credential: all dependencies are required")
	}

	return &DeleteCredential{d}, nil
}

// DeleteCommand is the input of DeleteCredential.
type DeleteCommand struct {
	Actor        appsession.Actor
	StepUpSecret string
	ID           string
}

// DeleteResult is the output of DeleteCredential.
type DeleteResult struct {
	Outcome Outcome
	Reason  Reason
}

// Execute deletes the key. A refusal spends nothing: the ticket stays for a better try.
func (u *DeleteCredential) Execute(ctx context.Context, cmd DeleteCommand) (DeleteResult, error) {
	id, idErr := dpasskey.ParseID(cmd.ID)
	now := u.Clock.Now()

	var result DeleteResult

	err := u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if _, ok, err := appsession.ActiveSession(ctx, st, cmd.Actor, now); err != nil {
			return err
		} else if !ok {
			result = DeleteResult{Outcome: OutcomeDenied, Reason: ReasonNoSession}
			return nil
		}

		ticket, ok, err := StepUpTicket(ctx, st, u.Tickets, cmd.StepUpSecret, cmd.Actor, dpasskey.OperationDeletePasskey, now)
		if err != nil {
			return err
		}

		if !ok {
			result = DeleteResult{Outcome: OutcomeStepUpRequired, Reason: ReasonStepUp}
			return nil
		}

		if idErr != nil {
			result = DeleteResult{Outcome: OutcomeNotFound, Reason: ReasonUnknownKeyID}
			return nil
		}

		err = st.Credentials.Delete(ctx, cmd.Actor.UserID, id)
		switch {
		case errors.Is(err, port.ErrNotFound):
			result = DeleteResult{Outcome: OutcomeNotFound, Reason: ReasonUnknownKeyID}
			return nil
		case errors.Is(err, port.ErrLastCredential):
			result = DeleteResult{Outcome: OutcomeConflict, Reason: ReasonLastKey}
			return nil
		case err != nil:
			return fmt.Errorf("delete credential: %w", err)
		}

		if err := SpendStepUp(ctx, st, ticket, cmd.Actor, dpasskey.OperationDeletePasskey, now); err != nil {
			return err
		}

		if err := st.Audit.Record(ctx, port.AuditEvent{
			Type: port.AuditPasskeyDeleted, Result: port.AuditSuccess, UserID: cmd.Actor.UserID, SessionID: cmd.Actor.SessionID, At: now,
		}); err != nil {
			return fmt.Errorf("record audit event: %w", err)
		}
		// A key that is lost or stolen is deleted so that it stops opening the account; the sessions it
		// opened must stop with it. The session does not remember its key, so every other one goes.
		if err := appsession.RevokeOthers(ctx, st, cmd.Actor.UserID, cmd.Actor.SessionID, now, "key_deleted"); err != nil {
			return err
		}

		result = DeleteResult{Outcome: OutcomeOK}

		return nil
	})
	if err != nil {
		return DeleteResult{}, fmt.Errorf("delete credential: %w", err)
	}

	return result, nil
}
