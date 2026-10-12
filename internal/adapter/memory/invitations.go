package memory

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/identity"
)

type invitations struct{ tx *state }

func (r *invitations) Save(_ context.Context, inv *identity.Invitation) error {
	r.tx.invitations[inv.Email().String()] = inv.Record()
	return nil
}

func (r *invitations) FindActive(_ context.Context, email identity.Email, now time.Time) (*identity.Invitation, error) {
	rec, ok := r.tx.invitations[email.String()]
	if !ok {
		return nil, port.ErrNotFound
	}
	inv, err := identity.RestoreInvitation(rec)
	if err != nil {
		return nil, fmt.Errorf("restore invitation: %w", err)
	}
	if !inv.Active(now) {
		return nil, port.ErrNotFound
	}
	return inv, nil
}

func (r *invitations) Consume(ctx context.Context, email identity.Email, now time.Time) (bool, error) {
	if _, err := r.FindActive(ctx, email, now); err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return false, nil
		}
		return false, err
	}
	delete(r.tx.invitations, email.String())
	return true, nil
}

func (r *invitations) Delete(_ context.Context, email identity.Email) (bool, error) {
	_, ok := r.tx.invitations[email.String()]
	delete(r.tx.invitations, email.String())
	return ok, nil
}

func (r *invitations) List(_ context.Context) ([]*identity.Invitation, error) {
	out := make([]*identity.Invitation, 0, len(r.tx.invitations))
	for _, rec := range r.tx.invitations {
		inv, err := identity.RestoreInvitation(rec)
		if err != nil {
			return nil, fmt.Errorf("restore invitation: %w", err)
		}
		out = append(out, inv)
	}
	slices.SortFunc(out, func(a, b *identity.Invitation) int {
		if c := a.CreatedAt().Compare(b.CreatedAt()); c != 0 {
			return c
		}
		return strings.Compare(a.Email().String(), b.Email().String())
	})
	return out, nil
}
