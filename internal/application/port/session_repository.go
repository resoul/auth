package port

import (
	"context"
	"time"

	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/session"
)

// SessionRepository stores device sessions.
type SessionRepository interface {
	// Create stores a new session.
	Create(ctx context.Context, s *session.Session) error
	// Get loads a session without locking it, for readers that change nothing, such as
	// the check of an access token. It returns ErrNotFound.
	Get(ctx context.Context, id session.ID) (*session.Session, error)
	// ListActive returns the user's sessions that are active at now (not revoked, not idle
	// or absolutely expired), most recently active first, at most limit of them.
	ListActive(ctx context.Context, userID identity.UserID, now time.Time, limit int) ([]*session.Session, error)
	// GetForUpdate loads a session and keeps it locked until the transaction ends.
	// Refresh and sign-out both lock the session first, so a revoked session cannot
	// receive new tokens. It returns ErrNotFound.
	GetForUpdate(ctx context.Context, id session.ID) (*session.Session, error)
	// Save writes the changed state of a session loaded by GetForUpdate.
	Save(ctx context.Context, s *session.Session) error
	// RevokeAllForUser revokes every session of the user that is not revoked yet. It queues on the user row, so a
	// session being issued at the same time (the issuer holds GetForShare) is either seen and revoked, or opened
	// after the revocation by a request that finds its own proof revoked.
	RevokeAllForUser(ctx context.Context, userID identity.UserID, now time.Time) error
	// RevokeOthersForUser revokes every session of the user except keep that is not revoked yet.
	RevokeOthersForUser(ctx context.Context, userID identity.UserID, keep session.ID, now time.Time) error
	// History tells what the sessions the store still keeps, ended ones too, say about a sign-in that is about to
	// open one: whether the user has any, and whether one was opened from this client binding.
	History(ctx context.Context, userID identity.UserID, binding identity.BindingHash) (SessionHistory, error)
}

// SessionHistory is what a user's kept sessions say about a client binding.
type SessionHistory struct {
	// Any is true when the user has at least one session.
	Any bool
	// ThisBinding is true when a session was opened from the binding.
	ThisBinding bool
}

// NewClient reports whether a sign-in comes from a client the user has not used before: the account has a
// history, and the binding is not in it. The first sign-in of an account is not news to its owner.
func (h SessionHistory) NewClient() bool { return h.Any && !h.ThisBinding }
