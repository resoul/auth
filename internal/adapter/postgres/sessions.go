package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"airlance.org/auth/internal/adapter/postgres/sqlc"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/domain/session"
)

type sessions struct{ q *sqlc.Queries }

func (r *sessions) Create(ctx context.Context, s *session.Session) error {
	rec := s.Record()
	id, err := toUUID(rec.ID.String())
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	userID, err := userUUID(rec.UserID)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	err = r.q.CreateSession(ctx, sqlc.CreateSessionParams{
		ID: id, UserID: userID, BindingHash: rec.Binding.Bytes(), Amr: rec.AMR,
		AuthTime: dbTime(rec.AuthTime), DeviceName: rec.DeviceName, CreatedAt: dbTime(rec.CreatedAt),
		LastActiveAt: dbTime(rec.LastActiveAt), IdleExpiresAt: dbTime(rec.IdleExpiresAt),
		ExpiresAt: dbTime(rec.ExpiresAt), RevokedAt: dbTimePtr(rec.RevokedAt),
	})
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

func (r *sessions) GetForUpdate(ctx context.Context, id session.ID) (*session.Session, error) {
	return r.load(ctx, id, r.q.GetSessionForUpdate)
}

func (r *sessions) Get(ctx context.Context, id session.ID) (*session.Session, error) {
	return r.load(ctx, id, r.q.GetSession)
}

// load reads one session with the given query: with or without a row lock.
func (r *sessions) load(ctx context.Context, id session.ID, query func(context.Context, uuid.UUID) (sqlc.Session, error)) (*session.Session, error) {
	u, err := toUUID(id.String())
	if err != nil {
		return nil, fmt.Errorf("load session: %w", err)
	}
	row, err := query(ctx, u)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load session: %w", err)
	}
	return sessionFromRow(row)
}

func (r *sessions) ListActive(ctx context.Context, userID identity.UserID, now time.Time, limit int) ([]*session.Session, error) {
	u, err := userUUID(userID)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	rows, err := r.q.ListActiveSessions(ctx, sqlc.ListActiveSessionsParams{UserID: u, Now: dbTime(now), MaxRows: int32(limit)})
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	out := make([]*session.Session, 0, len(rows))
	for _, row := range rows {
		s, err := sessionFromRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func sessionFromRow(row sqlc.Session) (*session.Session, error) {
	sid, err := session.ParseID(row.ID.String())
	if err != nil {
		return nil, fmt.Errorf("stored session id: %w", err)
	}
	userID, err := identity.ParseUserID(row.UserID.String())
	if err != nil {
		return nil, fmt.Errorf("stored session user: %w", err)
	}
	binding, err := identity.NewBindingHash(row.BindingHash)
	if err != nil {
		return nil, fmt.Errorf("stored session binding: %w", err)
	}
	return session.Restore(session.Record{
		ID: sid, UserID: userID, Binding: binding, AMR: row.Amr, AuthTime: goTime(row.AuthTime),
		DeviceName: row.DeviceName, CreatedAt: goTime(row.CreatedAt), LastActiveAt: goTime(row.LastActiveAt),
		IdleExpiresAt: goTime(row.IdleExpiresAt), ExpiresAt: goTime(row.ExpiresAt), RevokedAt: goTimePtr(row.RevokedAt),
	})
}

func (r *sessions) Save(ctx context.Context, s *session.Session) error {
	rec := s.Record()
	id, err := toUUID(rec.ID.String())
	if err != nil {
		return fmt.Errorf("save session: %w", err)
	}
	n, err := r.q.UpdateSession(ctx, sqlc.UpdateSessionParams{
		ID: id, LastActiveAt: dbTime(rec.LastActiveAt), IdleExpiresAt: dbTime(rec.IdleExpiresAt), RevokedAt: dbTimePtr(rec.RevokedAt),
	})
	if err != nil {
		return fmt.Errorf("save session: %w", err)
	}
	if n == 0 {
		return port.ErrNotFound
	}
	return nil
}

func (r *sessions) RevokeOthersForUser(ctx context.Context, userID identity.UserID, keep session.ID, now time.Time) error {
	u, err := userUUID(userID)
	if err != nil {
		return fmt.Errorf("revoke other sessions: %w", err)
	}
	k, err := toUUID(keep.String())
	if err != nil {
		return fmt.Errorf("revoke other sessions: %w", err)
	}
	if _, err := lockUser(ctx, r.q, userID); err != nil {
		return fmt.Errorf("revoke other sessions: %w", err)
	}
	t := dbTime(now)
	if err := r.q.RevokeOtherUserSessions(ctx, sqlc.RevokeOtherUserSessionsParams{UserID: u, ID: k, RevokedAt: &t}); err != nil {
		return fmt.Errorf("revoke other sessions: %w", err)
	}
	return nil
}

func (r *sessions) RevokeAllForUser(ctx context.Context, userID identity.UserID, now time.Time) error {
	u, err := userUUID(userID)
	if err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}
	if _, err := lockUser(ctx, r.q, userID); err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}
	t := dbTime(now)
	if err := r.q.RevokeUserSessions(ctx, sqlc.RevokeUserSessionsParams{UserID: u, RevokedAt: &t}); err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}
	return nil
}

func (r *sessions) History(ctx context.Context, userID identity.UserID, binding identity.BindingHash) (port.SessionHistory, error) {
	u, err := userUUID(userID)
	if err != nil {
		return port.SessionHistory{}, fmt.Errorf("session history: %w", err)
	}
	row, err := r.q.SessionHistory(ctx, sqlc.SessionHistoryParams{UserID: u, BindingHash: binding.Bytes()})
	if err != nil {
		return port.SessionHistory{}, fmt.Errorf("session history: %w", err)
	}
	return port.SessionHistory{Any: row.AnySession, ThisBinding: row.ThisBinding}, nil
}
