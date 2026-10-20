package crypto_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"go.airlance.org/auth/internal/adapter/crypto"
	"go.airlance.org/auth/internal/domain/authflow"
)

func TestNewFlowIDIsValidAndUnique(t *testing.T) {
	var gen crypto.Random

	seen := make(map[authflow.FlowID]bool)

	for i := 0; i < 100; i++ {
		flowID, err := gen.NewFlowID()
		if err != nil {
			t.Fatalf("NewFlowID: %v", err)
		}

		if _, err := authflow.ParseFlowID(flowID.String()); err != nil {
			t.Fatalf("generated id %q does not parse: %v", flowID, err)
		}

		if seen[flowID] {
			t.Fatalf("duplicate id %q", flowID)
		}

		seen[flowID] = true
	}
}

func TestNewFlowIDUsesTheRandomBytes(t *testing.T) {
	source := bytes.NewReader(bytes.Repeat([]byte{0xff}, 16))

	flowID, err := crypto.Random{Source: source}.NewFlowID()
	if err != nil {
		t.Fatalf("NewFlowID: %v", err)
	}

	if want := strings.Repeat("_", 21) + "w"; flowID.String() != want {
		t.Errorf("flow id = %q, want %q", flowID, want)
	}
}

func TestNewFlowIDFailsWithoutEnoughRandomness(t *testing.T) {
	for name, source := range map[string]*bytes.Reader{
		"empty": bytes.NewReader(nil),
		"short": bytes.NewReader(make([]byte, 15)),
	} {
		t.Run(name, func(t *testing.T) {
			flowID, err := crypto.Random{Source: source}.NewFlowID()
			if err == nil || !flowID.IsZero() {
				t.Fatalf("NewFlowID = %q, %v; want error and zero id", flowID, err)
			}
		})
	}
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

func TestNewFlowIDWrapsSourceError(t *testing.T) {
	boom := errors.New("entropy unavailable")

	_, err := crypto.Random{Source: failingReader{err: boom}}.NewFlowID()
	if !errors.Is(err, boom) {
		t.Errorf("error = %v, want wrapped %v", err, boom)
	}
}
