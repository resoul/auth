package memory

import (
	"context"
	"fmt"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/authflow"
)

type flows struct{ tx *state }

func (r *flows) Create(_ context.Context, f *authflow.Flow) error {
	key := f.ID().String()
	if _, exists := r.tx.flows[key]; exists {
		return fmt.Errorf("create flow: id already exists")
	}

	r.tx.flows[key] = f.Record()

	return nil
}

func (r *flows) Get(ctx context.Context, id authflow.FlowID) (*authflow.Flow, error) {
	return r.GetForUpdate(ctx, id)
}

func (r *flows) GetForUpdate(_ context.Context, id authflow.FlowID) (*authflow.Flow, error) {
	rec, ok := r.tx.flows[id.String()]
	if !ok {
		return nil, port.ErrNotFound
	}

	f, err := authflow.Restore(rec)
	if err != nil {
		return nil, fmt.Errorf("restore flow: %w", err)
	}

	return f, nil
}

func (r *flows) Save(_ context.Context, f *authflow.Flow) error {
	key := f.ID().String()
	if _, ok := r.tx.flows[key]; !ok {
		return port.ErrNotFound
	}

	r.tx.flows[key] = f.Record()

	return nil
}
