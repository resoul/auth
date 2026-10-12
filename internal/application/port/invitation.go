package port

import (
	"context"
	"time"

	"airlance.org/auth/internal/domain/identity"
)

// InvitationRepository stores the permissions to register in the invite-only mode.
type InvitationRepository interface {
	// Save stores an invitation, or renews the expiry of the one the address already has.
	Save(ctx context.Context, inv *identity.Invitation) error
	// FindActive returns the invitation of the address that is active at now, or ErrNotFound.
	FindActive(ctx context.Context, email identity.Email, now time.Time) (*identity.Invitation, error)
	// Consume removes the active invitation of the address and reports whether there was one. Of two
	// concurrent calls for one invitation only one reports true.
	Consume(ctx context.Context, email identity.Email, now time.Time) (bool, error)
	// Delete removes the invitation of the address, active or not, and reports whether there was one.
	Delete(ctx context.Context, email identity.Email) (bool, error)
	// List returns the invitations, oldest first, with the expired ones the sweep has not removed yet.
	List(ctx context.Context) ([]*identity.Invitation, error)
}
