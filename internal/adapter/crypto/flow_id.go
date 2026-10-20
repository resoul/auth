package crypto

import (
	"crypto/rand"
	"fmt"
	"io"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/authflow"
)

var _ port.FlowIDGenerator = Random{}

type Random struct {
	Source io.Reader
}

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
