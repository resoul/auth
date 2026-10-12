package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"airlance.org/auth/internal/adapter/postgres/sqlc"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/identity"
)

type recognized struct{ q *sqlc.Queries }

func (r *recognized) Register(ctx context.Context, candidate *identity.RecognizedClient) (*identity.RecognizedClient, error) {
	rec := candidate.Record()
	id, err := toUUID(rec.ID.String())
	if err != nil {
		return nil, fmt.Errorf("register recognized client: %w", err)
	}
	userID, err := userUUID(rec.UserID)
	if err != nil {
		return nil, fmt.Errorf("register recognized client: %w", err)
	}
	row, err := r.q.RegisterRecognizedClient(ctx, sqlc.RegisterRecognizedClientParams{
		ID: id, UserID: userID, Email: rec.Email.String(), BindingHash: rec.Binding.Bytes(),
		VerifiedAt: dbTime(rec.VerifiedAt), ExpiresAt: dbTime(rec.ExpiresAt),
	})
	if err != nil {
		return nil, fmt.Errorf("register recognized client: %w", err)
	}
	return recognizedFromRow(row)
}

func (r *recognized) FindActive(ctx context.Context, email identity.Email, binding identity.BindingHash, now time.Time) (*identity.RecognizedClient, error) {
	row, err := r.q.FindActiveRecognizedClient(ctx, sqlc.FindActiveRecognizedClientParams{
		Email: email.String(), BindingHash: binding.Bytes(), ExpiresAt: dbTime(now),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("find recognized client: %w", err)
	}
	return recognizedFromRow(row)
}

func (r *recognized) Extend(ctx context.Context, userID identity.UserID, binding identity.BindingHash, now time.Time) error {
	user, err := userUUID(userID)
	if err != nil {
		return fmt.Errorf("extend recognized client: %w", err)
	}
	n, err := r.q.ExtendRecognizedClient(ctx, sqlc.ExtendRecognizedClientParams{
		UserID: user, BindingHash: binding.Bytes(),
		NewExpiresAt: dbTime(now.Add(identity.RecognitionTTL)), Now: dbTime(now),
	})
	if err != nil {
		return fmt.Errorf("extend recognized client: %w", err)
	}
	if n == 0 {
		return port.ErrNotFound
	}
	return nil
}

func (r *recognized) Revoke(ctx context.Context, userID identity.UserID, binding identity.BindingHash, now time.Time) error {
	user, err := userUUID(userID)
	if err != nil {
		return fmt.Errorf("revoke recognized client: %w", err)
	}
	t := dbTime(now)
	if err := r.q.RevokeRecognizedClient(ctx, sqlc.RevokeRecognizedClientParams{
		UserID: user, BindingHash: binding.Bytes(), RevokedAt: &t,
	}); err != nil {
		return fmt.Errorf("revoke recognized client: %w", err)
	}
	return nil
}

func (r *recognized) RevokeAll(ctx context.Context, userID identity.UserID, now time.Time) error {
	user, err := userUUID(userID)
	if err != nil {
		return fmt.Errorf("revoke recognized clients: %w", err)
	}
	t := dbTime(now)
	if err := r.q.RevokeAllRecognizedClients(ctx, sqlc.RevokeAllRecognizedClientsParams{UserID: user, RevokedAt: &t}); err != nil {
		return fmt.Errorf("revoke recognized clients: %w", err)
	}
	return nil
}

func recognizedFromRow(row sqlc.RecognizedClient) (*identity.RecognizedClient, error) {
	id, err := identity.ParseRecognizedClientID(row.ID.String())
	if err != nil {
		return nil, fmt.Errorf("stored recognized client id: %w", err)
	}
	userID, err := identity.ParseUserID(row.UserID.String())
	if err != nil {
		return nil, fmt.Errorf("stored recognized client user: %w", err)
	}
	email, err := identity.ParseEmail(row.Email)
	if err != nil {
		return nil, fmt.Errorf("stored recognized client email: %w", err)
	}
	binding, err := identity.NewBindingHash(row.BindingHash)
	if err != nil {
		return nil, fmt.Errorf("stored recognized client binding: %w", err)
	}
	return identity.RestoreRecognizedClient(identity.RecognizedClientRecord{
		ID: id, UserID: userID, Email: email, Binding: binding,
		VerifiedAt: goTime(row.VerifiedAt), ExpiresAt: goTime(row.ExpiresAt), RevokedAt: goTimePtr(row.RevokedAt),
	})
}
