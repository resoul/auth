package emailauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/authflow"
)

// recognitionLost reports whether a flow of the recognized class has lost its record,
// which was revoked or expired after the flow began. The request is then refused
// before it spends anything, and the client has to start a new flow:
// A successful proof records a recognized client for future quota accounting.
func recognitionLost(ctx context.Context, st port.Stores, flow *authflow.Flow, now time.Time) (bool, error) {
	if flow.QuotaClass() != authflow.QuotaRecognized {
		return false, nil
	}

	rc, err := st.Recognized.FindActive(ctx, flow.Email(), flow.BindingHash(), now)
	if errors.Is(err, port.ErrNotFound) {
		return true, nil
	}

	if err != nil {
		return false, fmt.Errorf("look up recognized client: %w", err)
	}

	return rc.ID() != flow.RecognizedClientID(), nil
}
