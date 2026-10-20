package memory

import (
	"context"
	"fmt"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/deviceauth"
)

type devices struct{ tx *state }

func (r *devices) Create(_ context.Context, req *deviceauth.Request) error {
	if _, ok := r.tx.devices[req.ID().String()]; ok {
		return fmt.Errorf("device request %s already exists", req.ID())
	}

	r.tx.devices[req.ID().String()] = req.Record()

	return nil
}

func (r *devices) Get(ctx context.Context, id deviceauth.RequestID) (*deviceauth.Request, error) {
	return r.GetForUpdate(ctx, id)
}

func (r *devices) GetForUpdate(_ context.Context, id deviceauth.RequestID) (*deviceauth.Request, error) {
	rec, ok := r.tx.devices[id.String()]
	if !ok {
		return nil, port.ErrNotFound
	}

	req, err := deviceauth.Restore(rec)
	if err != nil {
		return nil, fmt.Errorf("restore device request: %w", err)
	}

	return req, nil
}

func (r *devices) Save(_ context.Context, req *deviceauth.Request) error {
	if _, ok := r.tx.devices[req.ID().String()]; !ok {
		return port.ErrNotFound
	}

	r.tx.devices[req.ID().String()] = req.Record()

	return nil
}
