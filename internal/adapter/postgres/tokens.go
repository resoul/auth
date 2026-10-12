package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"airlance.org/auth/internal/adapter/postgres/sqlc"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/domain/session"
	"airlance.org/auth/internal/domain/token"
)

// pgUniqueViolation is the SQLSTATE of a violated unique constraint or index.
const pgUniqueViolation = "23505"

type tokens struct{ q *sqlc.Queries }

func (r *tokens) Create(ctx context.Context, t *token.RefreshToken) error {
	rec := t.Record()
	id, err := toUUID(rec.ID.String())
	if err != nil {
		return fmt.Errorf("create refresh token: %w", err)
	}
	sessionID, err := toUUID(rec.SessionID.String())
	if err != nil {
		return fmt.Errorf("create refresh token: %w", err)
	}
	familyID, err := toUUID(rec.FamilyID.String())
	if err != nil {
		return fmt.Errorf("create refresh token: %w", err)
	}
	var parentID *uuid.UUID
	if !rec.ParentID.IsZero() {
		p, err := toUUID(rec.ParentID.String())
		if err != nil {
			return fmt.Errorf("create refresh token: %w", err)
		}
		parentID = &p
	}
	err = r.q.CreateRefreshToken(ctx, sqlc.CreateRefreshTokenParams{
		ID: id, SessionID: sessionID, FamilyID: familyID, ParentID: parentID, TokenHash: rec.Hash.Bytes(),
		CreatedAt: dbTime(rec.CreatedAt), ExpiresAt: dbTime(rec.ExpiresAt),
		UsedAt: dbTimePtr(rec.UsedAt), RevokedAt: dbTimePtr(rec.RevokedAt),
	})
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation &&
		(pgErr.ConstraintName == "refresh_tokens_hash_unique" || pgErr.ConstraintName == "refresh_one_live_child") {
		return port.ErrTokenConflict
	}
	if err != nil {
		return fmt.Errorf("create refresh token: %w", err)
	}
	return nil
}

func (r *tokens) FindByHash(ctx context.Context, hash token.Hash) (*token.RefreshToken, error) {
	row, err := r.q.FindRefreshTokenByHash(ctx, hash.Bytes())
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find refresh token: %w", err)
	}
	return tokenFromRow(row)
}

func (r *tokens) GetForUpdate(ctx context.Context, id token.ID) (*token.RefreshToken, error) {
	u, err := toUUID(id.String())
	if err != nil {
		return nil, fmt.Errorf("load refresh token: %w", err)
	}
	row, err := r.q.GetRefreshTokenForUpdate(ctx, u)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load refresh token: %w", err)
	}
	return tokenFromRow(row)
}

func tokenFromRow(row sqlc.RefreshToken) (*token.RefreshToken, error) {
	id, err := token.ParseID(row.ID.String())
	if err != nil {
		return nil, fmt.Errorf("stored token id: %w", err)
	}
	sessionID, err := session.ParseID(row.SessionID.String())
	if err != nil {
		return nil, fmt.Errorf("stored token session: %w", err)
	}
	familyID, err := token.ParseFamilyID(row.FamilyID.String())
	if err != nil {
		return nil, fmt.Errorf("stored token family: %w", err)
	}
	var parentID token.ID
	if row.ParentID != nil {
		parentID, err = token.ParseID(row.ParentID.String())
		if err != nil {
			return nil, fmt.Errorf("stored token parent: %w", err)
		}
	}
	hash, err := token.NewHash(row.TokenHash)
	if err != nil {
		return nil, fmt.Errorf("stored token hash: %w", err)
	}
	return token.Restore(token.Record{
		ID: id, SessionID: sessionID, FamilyID: familyID, ParentID: parentID, Hash: hash,
		CreatedAt: goTime(row.CreatedAt), ExpiresAt: goTime(row.ExpiresAt),
		UsedAt: goTimePtr(row.UsedAt), RevokedAt: goTimePtr(row.RevokedAt),
	})
}

func (r *tokens) Save(ctx context.Context, t *token.RefreshToken) error {
	rec := t.Record()
	id, err := toUUID(rec.ID.String())
	if err != nil {
		return fmt.Errorf("save refresh token: %w", err)
	}
	n, err := r.q.UpdateRefreshToken(ctx, sqlc.UpdateRefreshTokenParams{
		ID: id, UsedAt: dbTimePtr(rec.UsedAt), RevokedAt: dbTimePtr(rec.RevokedAt),
	})
	if err != nil {
		return fmt.Errorf("save refresh token: %w", err)
	}
	if n == 0 {
		return port.ErrNotFound
	}
	return nil
}

func (r *tokens) RevokeBySession(ctx context.Context, sessionID session.ID, now time.Time) error {
	u, err := toUUID(sessionID.String())
	if err != nil {
		return fmt.Errorf("revoke refresh tokens: %w", err)
	}
	t := dbTime(now)
	if err := r.q.RevokeSessionTokens(ctx, sqlc.RevokeSessionTokensParams{SessionID: u, RevokedAt: &t}); err != nil {
		return fmt.Errorf("revoke refresh tokens: %w", err)
	}
	return nil
}

func (r *tokens) RevokeOthersForUser(ctx context.Context, userID identity.UserID, keep session.ID, now time.Time) error {
	u, err := userUUID(userID)
	if err != nil {
		return fmt.Errorf("revoke other refresh tokens: %w", err)
	}
	k, err := toUUID(keep.String())
	if err != nil {
		return fmt.Errorf("revoke other refresh tokens: %w", err)
	}
	if _, err := lockUser(ctx, r.q, userID); err != nil {
		return fmt.Errorf("revoke other refresh tokens: %w", err)
	}
	t := dbTime(now)
	if err := r.q.RevokeOtherUserTokens(ctx, sqlc.RevokeOtherUserTokensParams{UserID: u, ID: k, RevokedAt: &t}); err != nil {
		return fmt.Errorf("revoke other refresh tokens: %w", err)
	}
	return nil
}

func (r *tokens) RevokeAllForUser(ctx context.Context, userID identity.UserID, now time.Time) error {
	u, err := userUUID(userID)
	if err != nil {
		return fmt.Errorf("revoke refresh tokens: %w", err)
	}
	if _, err := lockUser(ctx, r.q, userID); err != nil {
		return fmt.Errorf("revoke refresh tokens: %w", err)
	}
	t := dbTime(now)
	if err := r.q.RevokeUserTokens(ctx, sqlc.RevokeUserTokensParams{UserID: u, RevokedAt: &t}); err != nil {
		return fmt.Errorf("revoke refresh tokens: %w", err)
	}
	return nil
}
