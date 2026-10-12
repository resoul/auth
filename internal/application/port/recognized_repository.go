package port

import (
	"context"
	"time"

	"airlance.org/auth/internal/domain/identity"
)

// RecognizedClientRepository stores the records that give a client its own quota class.
type RecognizedClientRepository interface {
	// Register records a successful verify for (user, binding). It creates candidate,
	// or renews the existing record of that pair, including a revoked or expired one,
	// because the email was just proven again. It returns the stored record, which
	// keeps the existing ID. It must be safe against concurrent registration of the
	// same pair: one record results.
	Register(ctx context.Context, candidate *identity.RecognizedClient) (*identity.RecognizedClient, error)
	// FindActive returns the record that is active at now for the confirmed email and
	// binding, or ErrNotFound. It is read-only and used when a flow chooses its class.
	FindActive(ctx context.Context, email identity.Email, binding identity.BindingHash, now time.Time) (*identity.RecognizedClient, error)
	// Extend applies a successful refresh to the active record of (user, binding).
	// It returns ErrNotFound when there is none; callers do not fail the exchange then.
	// It never restores a revoked or expired record.
	Extend(ctx context.Context, userID identity.UserID, binding identity.BindingHash, now time.Time) error
	// Revoke ends recognition of one binding of a user. A missing record is not an error.
	Revoke(ctx context.Context, userID identity.UserID, binding identity.BindingHash, now time.Time) error
	// RevokeAll ends recognition of every binding of a user.
	RevokeAll(ctx context.Context, userID identity.UserID, now time.Time) error
}
