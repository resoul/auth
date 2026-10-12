package passkey

import (
	"context"
	"fmt"

	"airlance.org/auth/internal/application/port"
	appsession "airlance.org/auth/internal/application/session"
)

// ListCredentials shows the passkeys of the acting user, oldest first.
type ListCredentials struct{ ManageDeps }

// NewListCredentials checks the dependencies once, at assembly time.
func NewListCredentials(d ManageDeps) (*ListCredentials, error) {
	if err := d.validate("list credentials"); err != nil {
		return nil, err
	}
	return &ListCredentials{d}, nil
}

// ListResult is the output of ListCredentials. Credentials is set only for OutcomeOK.
type ListResult struct {
	Outcome     Outcome
	Credentials []CredentialSummary
}

// Execute lists the keys. A session revoked since the access check gets nothing.
func (u *ListCredentials) Execute(ctx context.Context, actor appsession.Actor) (ListResult, error) {
	now := u.Clock.Now()
	result := ListResult{Outcome: OutcomeDenied}
	err := u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if _, ok, err := appsession.ActiveSession(ctx, st, actor, now); err != nil || !ok {
			return err
		}
		creds, err := st.Credentials.ListByUser(ctx, actor.UserID)
		if err != nil {
			return fmt.Errorf("list credentials: %w", err)
		}
		result = ListResult{Outcome: OutcomeOK}
		for _, c := range creds {
			result.Credentials = append(result.Credentials, summarize(c))
		}
		return nil
	})
	if err != nil {
		return ListResult{}, fmt.Errorf("list credentials: %w", err)
	}
	return result, nil
}
