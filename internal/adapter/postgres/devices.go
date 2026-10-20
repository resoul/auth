package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"go.airlance.org/auth/internal/adapter/postgres/sqlc"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/deviceauth"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/passkey"
	"go.airlance.org/auth/internal/domain/session"
)

type devices struct{ q *sqlc.Queries }

func (r *devices) Create(ctx context.Context, req *deviceauth.Request) error {
	args, err := deviceParams(req.Record())
	if err != nil {
		return fmt.Errorf("create device request: %w", err)
	}

	if err := r.q.CreateDeviceRequest(ctx, sqlc.CreateDeviceRequestParams(args)); err != nil {
		return fmt.Errorf("create device request: %w", err)
	}

	return nil
}

func (r *devices) Get(ctx context.Context, id deviceauth.RequestID) (*deviceauth.Request, error) {
	row, err := r.q.GetDeviceRequest(ctx, id.String())
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("get device request: %w", err)
	}

	return deviceFromRow(row)
}

func (r *devices) GetForUpdate(ctx context.Context, id deviceauth.RequestID) (*deviceauth.Request, error) {
	row, err := r.q.GetDeviceRequestForUpdate(ctx, id.String())
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("get device request: %w", err)
	}

	return deviceFromRow(row)
}

func (r *devices) Save(ctx context.Context, req *deviceauth.Request) error {
	rec := req.Record()

	args, err := deviceParams(rec)
	if err != nil {
		return fmt.Errorf("save device request: %w", err)
	}

	n, err := r.q.UpdateDeviceRequest(ctx, sqlc.UpdateDeviceRequestParams{
		ID: args.ID, State: args.State, Attempts: args.Attempts, UserID: args.UserID, SessionID: args.SessionID,
		DecidedAt: args.DecidedAt, RedeemedAt: args.RedeemedAt,
	})
	if err != nil {
		return fmt.Errorf("save device request: %w", err)
	}

	if n == 0 {
		return port.ErrNotFound
	}

	return nil
}

// deviceParams maps a record to the columns; sqlc's insert parameters have the same fields in the same order.
func deviceParams(rec deviceauth.Record) (sqlc.CreateDeviceRequestParams, error) {
	userID, err := optionalUserUUID(rec.UserID)
	if err != nil {
		return sqlc.CreateDeviceRequestParams{}, err
	}

	out := sqlc.CreateDeviceRequestParams{
		ID: rec.ID.String(), PollHash: rec.PollHash.Bytes(), BindingHash: rec.Binding.Bytes(), DeviceName: rec.DeviceName,
		PairingCode: rec.Code, State: string(rec.State), Attempts: int16(rec.Attempts), UserID: userID,
		CreatedAt: dbTime(rec.CreatedAt), ExpiresAt: dbTime(rec.ExpiresAt), DecidedAt: dbTimePtr(rec.DecidedAt), RedeemedAt: dbTimePtr(rec.RedeemedAt),
	}
	if !rec.SessionID.IsZero() {
		s, err := toUUID(rec.SessionID.String())
		if err != nil {
			return sqlc.CreateDeviceRequestParams{}, err
		}

		out.SessionID = &s
	}

	return out, nil
}

func deviceFromRow(row sqlc.DeviceRequest) (*deviceauth.Request, error) {
	id, err := deviceauth.ParseRequestID(row.ID)
	if err != nil {
		return nil, fmt.Errorf("stored device request id: %w", err)
	}

	poll, err := passkey.NewSecretHash(row.PollHash)
	if err != nil {
		return nil, fmt.Errorf("stored device request poll hash: %w", err)
	}

	binding, err := identity.NewBindingHash(row.BindingHash)
	if err != nil {
		return nil, fmt.Errorf("stored device request binding: %w", err)
	}

	userID, err := userFromOptional(row.UserID)
	if err != nil {
		return nil, fmt.Errorf("stored device request user: %w", err)
	}

	var sessionID session.ID
	if row.SessionID != nil {
		if sessionID, err = session.ParseID(row.SessionID.String()); err != nil {
			return nil, fmt.Errorf("stored device request session: %w", err)
		}
	}

	return deviceauth.Restore(deviceauth.Record{
		ID: id, PollHash: poll, Binding: binding, DeviceName: row.DeviceName, Code: row.PairingCode, State: deviceauth.State(row.State),
		Attempts: int(row.Attempts), UserID: userID, SessionID: sessionID, CreatedAt: goTime(row.CreatedAt), ExpiresAt: goTime(row.ExpiresAt),
		DecidedAt: goTimePtr(row.DecidedAt), RedeemedAt: goTimePtr(row.RedeemedAt),
	})
}
