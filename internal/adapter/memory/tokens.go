package memory

import (
	"context"
	"fmt"
	"time"

	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/domain/session"
	"airlance.org/auth/internal/domain/token"
)

type tokens struct{ tx *state }

// Create enforces the same invariants as the PostgreSQL constraints: a unique
// secret hash, an existing session, and at most one live child per parent.
func (r *tokens) Create(_ context.Context, t *token.RefreshToken) error {
	rec := t.Record()
	if _, exists := r.tx.tokens[rec.ID.String()]; exists {
		return fmt.Errorf("create refresh token: id already exists")
	}
	if _, ok := r.tx.sessions[rec.SessionID.String()]; !ok {
		return fmt.Errorf("create refresh token: session does not exist")
	}
	for _, other := range r.tx.tokens {
		if other.Hash == rec.Hash {
			return port.ErrTokenConflict
		}
		if !rec.ParentID.IsZero() && other.ParentID == rec.ParentID && other.RevokedAt.IsZero() && rec.RevokedAt.IsZero() {
			return port.ErrTokenConflict
		}
	}
	r.tx.tokens[rec.ID.String()] = rec
	return nil
}

func (r *tokens) load(rec token.Record) (*token.RefreshToken, error) {
	t, err := token.Restore(rec)
	if err != nil {
		return nil, fmt.Errorf("restore refresh token: %w", err)
	}
	return t, nil
}

func (r *tokens) FindByHash(_ context.Context, hash token.Hash) (*token.RefreshToken, error) {
	for _, rec := range r.tx.tokens {
		if rec.Hash == hash {
			return r.load(rec)
		}
	}
	return nil, port.ErrNotFound
}

func (r *tokens) GetForUpdate(_ context.Context, id token.ID) (*token.RefreshToken, error) {
	rec, ok := r.tx.tokens[id.String()]
	if !ok {
		return nil, port.ErrNotFound
	}
	return r.load(rec)
}

func (r *tokens) Save(_ context.Context, t *token.RefreshToken) error {
	key := t.ID().String()
	existing, ok := r.tx.tokens[key]
	if !ok {
		return port.ErrNotFound
	}
	rec := t.Record()
	if !existing.UsedAt.IsZero() {
		rec.UsedAt = existing.UsedAt // the used and revoked marks are never cleared
	}
	if !existing.RevokedAt.IsZero() {
		rec.RevokedAt = existing.RevokedAt
	}
	r.tx.tokens[key] = rec
	return nil
}

func (r *tokens) revokeWhere(match func(token.Record) bool, now time.Time) error {
	for key, rec := range r.tx.tokens {
		if !match(rec) {
			continue
		}
		t, err := r.load(rec)
		if err != nil {
			return err
		}
		t.Revoke(now)
		r.tx.tokens[key] = t.Record()
	}
	return nil
}

func (r *tokens) RevokeBySession(_ context.Context, sessionID session.ID, now time.Time) error {
	return r.revokeWhere(func(rec token.Record) bool { return rec.SessionID == sessionID }, now)
}

func (r *tokens) RevokeOthersForUser(_ context.Context, userID identity.UserID, keep session.ID, now time.Time) error {
	return r.revokeWhere(func(rec token.Record) bool {
		sess, ok := r.tx.sessions[rec.SessionID.String()]
		return ok && sess.UserID == userID && rec.SessionID != keep
	}, now)
}

func (r *tokens) RevokeAllForUser(_ context.Context, userID identity.UserID, now time.Time) error {
	return r.revokeWhere(func(rec token.Record) bool {
		sess, ok := r.tx.sessions[rec.SessionID.String()]
		return ok && sess.UserID == userID
	}, now)
}
