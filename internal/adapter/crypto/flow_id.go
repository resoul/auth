package crypto

import (
	"crypto/rand"
	"fmt"
	"io"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/authflow"
)

var _ port.FlowIDGenerator = Random{}

// Random draws secrets from a random source. The zero value uses crypto/rand.
type Random struct {
	// Source overrides crypto/rand in tests of this package only.
	Source io.Reader
}

// NewFlowID returns 16 random bytes encoded as a flow identifier.
func (r Random) NewFlowID() (authflow.FlowID, error) {
	source := r.Source
	if source == nil {
		source = rand.Reader
	}

	var raw [16]byte
	if _, err := io.ReadFull(source, raw[:]); err != nil {
		return authflow.FlowID{}, fmt.Errorf("generate flow id: %w", err)
	}

	return authflow.NewFlowID(raw), nil
}
