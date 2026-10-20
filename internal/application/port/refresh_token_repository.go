package port

import (
	"context"
	"errors"
	"time"

	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/session"
	"go.airlance.org/auth/internal/domain/token"
)

// ErrTokenConflict reports a violated token invariant: a duplicate secret hash or
// a second live child of one parent.
var ErrTokenConflict = errors.New("refresh token conflict")

// RefreshTokenRepository stores refresh tokens.
type RefreshTokenRepository interface {
	// Create stores a token. It returns ErrTokenConflict when the hash exists or the
	// parent already has a live (not revoked) child.
	Create(ctx context.Context, t *token.RefreshToken) error
	// FindByHash looks a token up by the hash of its secret without locking it, to
	// learn its session. It returns ErrNotFound.
	FindByHash(ctx context.Context, hash token.Hash) (*token.RefreshToken, error)
	// GetForUpdate loads a token and keeps it locked until the transaction ends.
	// Callers lock the session first. It returns ErrNotFound.
	GetForUpdate(ctx context.Context, id token.ID) (*token.RefreshToken, error)
	// Save writes the changed state of a token loaded by GetForUpdate.
	Save(ctx context.Context, t *token.RefreshToken) error
	// RevokeBySession revokes every token of the session that is not revoked yet.
	RevokeBySession(ctx context.Context, sessionID session.ID, now time.Time) error
	// RevokeAllForUser revokes every token of every session of the user. It queues on the user row like
	// SessionRepository.RevokeAllForUser.
	RevokeAllForUser(ctx context.Context, userID identity.UserID, now time.Time) error
	// RevokeOthersForUser revokes every token of every session of the user except the session keep.
	RevokeOthersForUser(ctx context.Context, userID identity.UserID, keep session.ID, now time.Time) error
}
