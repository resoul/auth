package memory

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/domain/session"
)

type sessions struct{ tx *state }

func (r *sessions) Create(_ context.Context, s *session.Session) error {
	key := s.ID().String()
	if _, exists := r.tx.sessions[key]; exists {
		return fmt.Errorf("create session: id already exists")
	}
	r.tx.sessions[key] = s.Record()
	return nil
}

func (r *sessions) Get(ctx context.Context, id session.ID) (*session.Session, error) {
	return r.GetForUpdate(ctx, id)
}

func (r *sessions) ListActive(_ context.Context, userID identity.UserID, now time.Time, limit int) ([]*session.Session, error) {
	var out []*session.Session
	for _, rec := range r.tx.sessions {
		if rec.UserID != userID {
			continue
		}
		s, err := session.Restore(rec)
		if err != nil {
			return nil, fmt.Errorf("restore session: %w", err)
		}
		if s.Active(now) {
			out = append(out, s)
		}
	}
	slices.SortFunc(out, func(a, b *session.Session) int {
		if c := b.LastActiveAt().Compare(a.LastActiveAt()); c != 0 {
			return c
		}
		return strings.Compare(a.ID().String(), b.ID().String())
	})
	if limit >= 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (r *sessions) GetForUpdate(_ context.Context, id session.ID) (*session.Session, error) {
	rec, ok := r.tx.sessions[id.String()]
	if !ok {
		return nil, port.ErrNotFound
	}
	s, err := session.Restore(rec)
	if err != nil {
		return nil, fmt.Errorf("restore session: %w", err)
	}
	return s, nil
}

func (r *sessions) Save(_ context.Context, s *session.Session) error {
	key := s.ID().String()
	existing, ok := r.tx.sessions[key]
	if !ok {
		return port.ErrNotFound
	}
	rec := s.Record()
	if !existing.RevokedAt.IsZero() {
		rec.RevokedAt = existing.RevokedAt
	}
	r.tx.sessions[key] = rec
	return nil
}

func (r *sessions) RevokeOthersForUser(_ context.Context, userID identity.UserID, keep session.ID, now time.Time) error {
	for key, rec := range r.tx.sessions {
		if rec.UserID != userID || rec.ID == keep {
			continue
		}
		s, err := session.Restore(rec)
		if err != nil {
			return fmt.Errorf("restore session: %w", err)
		}
		s.Revoke(now)
		r.tx.sessions[key] = s.Record()
	}
	return nil
}

func (r *sessions) RevokeAllForUser(_ context.Context, userID identity.UserID, now time.Time) error {
	for key, rec := range r.tx.sessions {
		if rec.UserID != userID {
			continue
		}
		s, err := session.Restore(rec)
		if err != nil {
			return fmt.Errorf("restore session: %w", err)
		}
		s.Revoke(now)
		r.tx.sessions[key] = s.Record()
	}
	return nil
}

func (r *sessions) History(_ context.Context, userID identity.UserID, binding identity.BindingHash) (port.SessionHistory, error) {
	var h port.SessionHistory
	for _, rec := range r.tx.sessions {
		if rec.UserID != userID {
			continue
		}
		h.Any = true
		if rec.Binding.Equal(binding) {
			h.ThisBinding = true
		}
	}
	return h, nil
}
