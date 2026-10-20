package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"go.airlance.org/auth/internal/adapter/postgres/sqlc"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
)

type invitations struct{ q *sqlc.Queries }

func (r *invitations) Save(ctx context.Context, inv *identity.Invitation) error {
	rec := inv.Record()
	if err := r.q.SaveInvitation(ctx, sqlc.SaveInvitationParams{
		Email: rec.Email.String(), CreatedAt: dbTime(rec.CreatedAt), ExpiresAt: dbTime(rec.ExpiresAt),
	}); err != nil {
		return fmt.Errorf("save invitation: %w", err)
	}

	return nil
}

func (r *invitations) FindActive(ctx context.Context, email identity.Email, now time.Time) (*identity.Invitation, error) {
	row, err := r.q.FindActiveInvitation(ctx, sqlc.FindActiveInvitationParams{Email: email.String(), ExpiresAt: dbTime(now)})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("find invitation: %w", err)
	}

	return invitationFromRow(row)
}

func (r *invitations) Consume(ctx context.Context, email identity.Email, now time.Time) (bool, error) {
	n, err := r.q.ConsumeInvitation(ctx, sqlc.ConsumeInvitationParams{Email: email.String(), ExpiresAt: dbTime(now)})
	if err != nil {
		return false, fmt.Errorf("consume invitation: %w", err)
	}

	return n == 1, nil
}

func (r *invitations) Delete(ctx context.Context, email identity.Email) (bool, error) {
	n, err := r.q.DeleteInvitation(ctx, email.String())
	if err != nil {
		return false, fmt.Errorf("delete invitation: %w", err)
	}

	return n == 1, nil
}

func (r *invitations) List(ctx context.Context) ([]*identity.Invitation, error) {
	rows, err := r.q.ListInvitations(ctx)
	if err != nil {
		return nil, fmt.Errorf("list invitations: %w", err)
	}

	out := make([]*identity.Invitation, 0, len(rows))
	for _, row := range rows {
		inv, err := invitationFromRow(row)
		if err != nil {
			return nil, err
		}

		out = append(out, inv)
	}

	return out, nil
}

func invitationFromRow(row sqlc.Invitation) (*identity.Invitation, error) {
	email, err := identity.ParseEmail(row.Email)
	if err != nil {
		return nil, fmt.Errorf("stored invitation email: %w", err)
	}

	return identity.RestoreInvitation(identity.InvitationRecord{Email: email, CreatedAt: goTime(row.CreatedAt), ExpiresAt: goTime(row.ExpiresAt)})
}
