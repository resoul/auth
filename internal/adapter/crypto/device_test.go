package crypto_test

import (
	"bytes"
	"testing"

	"go.airlance.org/auth/internal/adapter/crypto"
	"go.airlance.org/auth/internal/domain/deviceauth"
)

func TestDeviceRequestIDsAreValidAndDistinct(t *testing.T) {
	seen := map[string]bool{}

	for i := 0; i < 200; i++ {
		id, err := crypto.Device{}.NewRequestID()
		if err != nil {
			t.Fatal(err)
		}

		if _, err := deviceauth.ParseRequestID(id.String()); err != nil || seen[id.String()] {
			t.Fatalf("id %q: %v (seen %v)", id, err, seen[id.String()])
		}

		seen[id.String()] = true
	}
}

func TestPairingCodesHaveSixDigitsIncludingLeadingZeros(t *testing.T) {
	// A source of zeros gives the smallest code: six zeros, not "0".
	code, err := crypto.Device{Source: bytes.NewReader(make([]byte, 64))}.NewPairingCode()
	if err != nil || code != "000000" {
		t.Fatalf("code = %q, %v", code, err)
	}

	for i := 0; i < 500; i++ {
		code, err := crypto.Device{}.NewPairingCode()
		if err != nil || !deviceauth.ValidPairingCode(code) {
			t.Fatalf("code %q: %v", code, err)
		}
	}
}

func TestADeadRandomSourceIsAnErrorNotAWeakCode(t *testing.T) {
	empty := crypto.Device{Source: bytes.NewReader(nil)}
	if _, err := empty.NewRequestID(); err == nil {
		t.Error("NewRequestID hid the failure of its source")
	}

	if code, err := empty.NewPairingCode(); err == nil || code != "" {
		t.Errorf("NewPairingCode = %q, %v; want an error and no code", code, err)
	}
}
