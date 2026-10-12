package passkey

import (
	"context"
	"fmt"

	"airlance.org/auth/internal/application/port"
	appsession "airlance.org/auth/internal/application/session"
	dpasskey "airlance.org/auth/internal/domain/passkey"
)

// RenameCredential changes the label of a passkey of the acting user. It needs no step-up: a
// label opens nothing.
type RenameCredential struct{ ManageDeps }

// NewRenameCredential checks the dependencies once, at assembly time.
func NewRenameCredential(d ManageDeps) (*RenameCredential, error) {
	if err := d.validate("rename credential"); err != nil {
		return nil, err
	}
	return &RenameCredential{d}, nil
}

// RenameCommand is the input of RenameCredential.
type RenameCommand struct {
	Actor appsession.Actor
	ID    string
	Name  string
}

// RenameResult is the output of RenameCredential.
type RenameResult struct {
	Outcome    Outcome
	Credential CredentialSummary
}

// Execute renames the key. Another user's key and a missing one look the same.
func (u *RenameCredential) Execute(ctx context.Context, cmd RenameCommand) (RenameResult, error) {
	if !dpasskey.ValidName(cmd.Name) {
		return RenameResult{}, fmt.Errorf("rename credential: %w", ErrInvalidName)
	}
	id, err := dpasskey.ParseID(cmd.ID)
	if err != nil {
		return RenameResult{Outcome: OutcomeNotFound}, nil
	}
	now := u.Clock.Now()
	result := RenameResult{Outcome: OutcomeNotFound}
	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if _, ok, err := appsession.ActiveSession(ctx, st, cmd.Actor, now); err != nil {
			return err
		} else if !ok {
			result.Outcome = OutcomeDenied
			return nil
		}
		creds, err := st.Credentials.ListByUser(ctx, cmd.Actor.UserID)
		if err != nil {
			return fmt.Errorf("list credentials: %w", err)
		}
		for _, c := range creds {
			if c.ID() != id {
				continue
			}
			// Load again under lock: the listing did not lock the key.
			locked, err := st.Credentials.GetForUpdate(ctx, c.CredentialID())
			if err != nil {
				return fmt.Errorf("load credential: %w", err)
			}
			if err := locked.Rename(cmd.Name); err != nil {
				return fmt.Errorf("rename: %w", err)
			}
			if err := st.Credentials.Save(ctx, locked); err != nil {
				return fmt.Errorf("store credential: %w", err)
			}
			result = RenameResult{Outcome: OutcomeOK, Credential: summarize(locked)}
			return nil
		}
		return nil
	})
	if err != nil {
		return RenameResult{}, fmt.Errorf("rename credential: %w", err)
	}
	return result, nil
}
