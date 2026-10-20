package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"go.airlance.org/auth/internal/adapter/postgres/sqlc"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/authflow"
	"go.airlance.org/auth/internal/domain/identity"
)

type flows struct{ q *sqlc.Queries }

func (r *flows) Create(ctx context.Context, f *authflow.Flow) error {
	rec := f.Record()

	generation, err := toInt64(rec.Generation)
	if err != nil {
		return fmt.Errorf("create flow: %w", err)
	}

	var clientID *uuid.UUID

	if !rec.RecognizedClientID.IsZero() {
		u, err := toUUID(rec.RecognizedClientID.String())
		if err != nil {
			return fmt.Errorf("create flow: %w", err)
		}

		clientID = &u
	}

	var userID *uuid.UUID

	if !rec.UserID.IsZero() {
		u, err := userUUID(rec.UserID)
		if err != nil {
			return fmt.Errorf("create flow: %w", err)
		}

		userID = &u
	}

	err = r.q.CreateFlow(ctx, sqlc.CreateFlowParams{
		ID: rec.ID.String(), Email: rec.Email.String(), Purpose: string(rec.Purpose),
		Generation: generation, Salt: rec.Salt, KeyID: rec.KeyID, BindingHash: rec.BindingHash.Bytes(),
		State: string(rec.State), CreatedAt: dbTime(rec.CreatedAt), ExpiresAt: dbTime(rec.ExpiresAt),
		Attempts: int32(rec.Attempts), ResendAfter: dbTime(rec.ResendAfter),
		QuotaClass: string(rec.QuotaClass), RecognizedClientID: clientID, UserID: userID,
	})
	if err != nil {
		return fmt.Errorf("create flow: %w", err)
	}

	return nil
}

func (r *flows) GetForUpdate(ctx context.Context, id authflow.FlowID) (*authflow.Flow, error) {
	row, err := r.q.GetFlowForUpdate(ctx, id.String())
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("load flow: %w", err)
	}

	return flowFromRow(sqlc.AuthFlow(row))
}

func (r *flows) Get(ctx context.Context, id authflow.FlowID) (*authflow.Flow, error) {
	row, err := r.q.GetFlow(ctx, id.String())
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("load flow: %w", err)
	}

	return flowFromRow(row)
}

func flowFromRow(row sqlc.AuthFlow) (*authflow.Flow, error) {
	id, err := authflow.ParseFlowID(row.ID)
	if err != nil {
		return nil, fmt.Errorf("stored flow id: %w", err)
	}

	email, err := identity.ParseEmail(row.Email)
	if err != nil {
		return nil, fmt.Errorf("stored flow email: %w", err)
	}

	binding, err := identity.NewBindingHash(row.BindingHash)
	if err != nil {
		return nil, fmt.Errorf("stored flow binding: %w", err)
	}

	var clientID identity.RecognizedClientID
	if row.RecognizedClientID != nil {
		clientID, err = identity.ParseRecognizedClientID(row.RecognizedClientID.String())
		if err != nil {
			return nil, fmt.Errorf("stored flow recognized client: %w", err)
		}
	}

	var userID identity.UserID
	if row.UserID != nil {
		userID, err = identity.ParseUserID(row.UserID.String())
		if err != nil {
			return nil, fmt.Errorf("stored flow user: %w", err)
		}
	}

	return authflow.Restore(authflow.Record{
		ID: id, Email: email, Purpose: authflow.Purpose(row.Purpose), Generation: uint64(row.Generation),
		Salt: row.Salt, KeyID: row.KeyID, BindingHash: binding, State: authflow.State(row.State),
		CreatedAt: goTime(row.CreatedAt), ExpiresAt: goTime(row.ExpiresAt), Attempts: int(row.Attempts),
		ResendAfter: goTime(row.ResendAfter), QuotaClass: authflow.QuotaClass(row.QuotaClass),
		RecognizedClientID: clientID, UserID: userID,
	})
}

func (r *flows) Save(ctx context.Context, f *authflow.Flow) error {
	rec := f.Record()

	generation, err := toInt64(rec.Generation)
	if err != nil {
		return fmt.Errorf("save flow: %w", err)
	}

	n, err := r.q.UpdateFlow(ctx, sqlc.UpdateFlowParams{
		ID: rec.ID.String(), Generation: generation, Salt: rec.Salt, KeyID: rec.KeyID,
		State: string(rec.State), Attempts: int32(rec.Attempts), ResendAfter: dbTime(rec.ResendAfter),
	})
	if err != nil {
		return fmt.Errorf("save flow: %w", err)
	}

	if n == 0 {
		return port.ErrNotFound
	}

	return nil
}
