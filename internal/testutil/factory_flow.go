package testutil

import (
	"encoding/binary"
	"fmt"

	"airlance.org/auth/internal/domain/authflow"
	"airlance.org/auth/internal/domain/identity"
)

// FlowSpec overrides the fields a scenario cares about. The zero value builds a
// pending login flow for an unknown client with the default policy.
type FlowSpec struct {
	// Email defaults to a unique address under example.test.
	Email   string
	Purpose authflow.Purpose
	// BindingSecret defaults to DefaultBindingSecret; compare with BindingHash.
	BindingSecret string
	QuotaClass    authflow.QuotaClass
	// RecognizedClientID is required with QuotaRecognized and is never created implicitly.
	RecognizedClientID identity.RecognizedClientID
	// UserID is required with PurposeChangeEmail and is never created implicitly.
	UserID identity.UserID
	// Salt defaults to 16 distinct bytes; KeyID defaults to "otp-test".
	Salt  []byte
	KeyID string
	// Policy defaults to authflow.DefaultPolicy().
	Policy *authflow.Policy
}

// DefaultKeyID is the OTP key ID of flows built without KeyID.
const DefaultKeyID = "otp-test"

// Flow starts a flow at the factory clock time.
func (f *Factory) Flow(spec FlowSpec) *authflow.Flow {
	f.t.Helper()
	id, err := f.IDs.NewFlowID()
	if err != nil {
		f.t.Fatalf("build flow id: %v", err)
	}
	raw := spec.Email
	if raw == "" {
		raw = fmt.Sprintf("flow-%s@example.test", id.String())
	}
	email, err := identity.ParseEmail(raw)
	if err != nil {
		f.t.Fatalf("build flow email %q: %v", raw, err)
	}
	purpose := spec.Purpose
	if purpose == "" {
		purpose = authflow.PurposeLogin
	}
	secret := spec.BindingSecret
	if secret == "" {
		secret = DefaultBindingSecret
	}
	class := spec.QuotaClass
	if class == "" {
		class = authflow.QuotaUnknown
	}
	salt := spec.Salt
	if salt == nil {
		salt = f.Salt()
	}
	keyID := spec.KeyID
	if keyID == "" {
		keyID = DefaultKeyID
	}
	policy := authflow.DefaultPolicy()
	if spec.Policy != nil {
		policy = *spec.Policy
	}

	flow, err := authflow.Start(authflow.StartParams{
		ID: id, Email: email, Purpose: purpose, Binding: BindingHash(secret),
		Salt: salt, KeyID: keyID, QuotaClass: class, RecognizedClientID: spec.RecognizedClientID, UserID: spec.UserID,
	}, f.Clock.Now(), policy)
	if err != nil {
		f.t.Fatalf("build flow: %v", err)
	}
	return flow
}

// Salt returns a fresh salt of the right length, distinct from earlier ones.
func (f *Factory) Salt() []byte {
	salt := make([]byte, authflow.SaltLength)
	binary.BigEndian.PutUint64(salt, f.IDs.n.Add(1))
	return salt
}
