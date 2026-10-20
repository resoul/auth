package testutil

import (
	"encoding/binary"
	"fmt"

	"go.airlance.org/auth/internal/domain/authflow"
	"go.airlance.org/auth/internal/domain/identity"
)

type FlowSpec struct {
	Email              string
	Purpose            authflow.Purpose
	BindingSecret      string
	QuotaClass         authflow.QuotaClass
	RecognizedClientID identity.RecognizedClientID
	UserID             identity.UserID
	Salt               []byte
	KeyID              string
	Policy             *authflow.Policy
}

const DefaultKeyID = "otp-test"

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

func (f *Factory) Salt() []byte {
	salt := make([]byte, authflow.SaltLength)
	binary.BigEndian.PutUint64(salt, f.IDs.n.Add(1))

	return salt
}
