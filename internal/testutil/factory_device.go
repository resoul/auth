package testutil

import (
	"crypto/rand"
	"fmt"

	"airlance.org/auth/internal/domain/deviceauth"
)

// DeviceSpec overrides the fields a scenario cares about.
type DeviceSpec struct {
	// PollSecret and BindingSecret default to values that match PollHash and BindingHash of the helpers below.
	PollSecret    string
	BindingSecret string
	DeviceName    string
	// PairingCode defaults to 123456.
	PairingCode string
}

// DeviceRequest builds a pending request made at the factory clock time. The ID is random: the identifier of a
// request is 16 random bytes and tests need not reproduce them.
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
