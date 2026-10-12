package port

import (
	"context"

	"airlance.org/auth/internal/domain/authflow"
)

// FlowRepository stores flows.
type FlowRepository interface {
	// Create stores a new flow.
	Create(ctx context.Context, f *authflow.Flow) error
	// Get loads a flow without locking it, for readers that change nothing, such as
	// the mail worker. It returns ErrNotFound.
	Get(ctx context.Context, id authflow.FlowID) (*authflow.Flow, error)
	// GetForUpdate loads a flow and keeps it locked until the transaction ends, so
	// resend, expiry and verify results are serialized. It returns ErrNotFound.
	GetForUpdate(ctx context.Context, id authflow.FlowID) (*authflow.Flow, error)
	// Save writes the changed state of a flow loaded by GetForUpdate.
	Save(ctx context.Context, f *authflow.Flow) error
}
