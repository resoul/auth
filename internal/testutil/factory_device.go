package testutil

import (
	"crypto/rand"
	"fmt"

	"go.airlance.org/auth/internal/domain/deviceauth"
)

type DeviceSpec struct {
	PollSecret    string
	BindingSecret string
	DeviceName    string
	// PairingCode defaults to 123456.
	PairingCode string
}

func (f *Factory) DeviceRequest(spec DeviceSpec) *deviceauth.Request {
	f.t.Helper()

	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		f.t.Fatal(err)
	}

	if spec.PollSecret == "" {
		spec.PollSecret = "poll-secret"
	}

	if spec.BindingSecret == "" {
		spec.BindingSecret = DefaultBindingSecret
	}

	if spec.PairingCode == "" {
		spec.PairingCode = "123456"
	}

	if spec.DeviceName == "" {
		spec.DeviceName = fmt.Sprintf("device-%x", raw[:2])
	}

	r, err := deviceauth.New(deviceauth.NewParams{
		ID: deviceauth.NewRequestID(raw), PollHash: SecretHash(spec.PollSecret), Binding: BindingHash(spec.BindingSecret),
		DeviceName: spec.DeviceName, PairingCode: spec.PairingCode,
	}, f.Clock.Now())
	if err != nil {
		f.t.Fatalf("build device request: %v", err)
	}

	return r
}
