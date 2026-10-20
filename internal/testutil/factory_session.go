package testutil

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/session"
	"go.airlance.org/auth/internal/domain/token"
)

type SessionSpec struct {
	User          *identity.User
	BindingSecret string
	DeviceName    string
	AMR           []string
	Policy        *session.Policy
}

func (f *Factory) Session(spec SessionSpec) *session.Session {
	f.t.Helper()

	if spec.User == nil {
		f.t.Fatal("build session: User is required")
	}

	id, err := f.IDs.NewSessionID()
	if err != nil {
		f.t.Fatalf("build session id: %v", err)
	}

	secret := spec.BindingSecret
	if secret == "" {
		secret = DefaultBindingSecret
	}

	device := spec.DeviceName
	if device == "" {
		device = "test device"
	}

	amr := spec.AMR
	if amr == nil {
		amr = []string{"otp"}
	}

	policy := session.DefaultPolicy()
	if spec.Policy != nil {
		policy = *spec.Policy
	}

	now := f.Clock.Now()

	s, err := session.New(session.NewParams{
		ID: id, UserID: spec.User.ID(), Binding: BindingHash(secret), AMR: amr, AuthTime: now, DeviceName: device,
	}, now, policy)
	if err != nil {
		f.t.Fatalf("build session: %v", err)
	}

	return s
}

type RefreshSpec struct {
	Session *session.Session
	Policy  *session.Policy
}

func hashOfSecret(secret string) token.Hash {
	raw, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil {
		panic(err) // unreachable: secrets are produced here
	}

	sum := sha256.Sum256(raw)

	h, err := token.NewHash(sum[:])
	if err != nil {
		panic(err) // unreachable: SHA-256 has the required length
	}

	return h
}

func (f *Factory) RefreshToken(spec RefreshSpec) (*token.RefreshToken, string) {
	f.t.Helper()

	if spec.Session == nil {
		f.t.Fatal("build refresh token: Session is required")
	}

	policy := session.DefaultPolicy()
	if spec.Policy != nil {
		policy = *spec.Policy
	}

	id, err := f.IDs.NewRefreshTokenID()
	if err != nil {
		f.t.Fatalf("build token id: %v", err)
	}

	family, err := f.IDs.NewFamilyID()
	if err != nil {
		f.t.Fatalf("build family id: %v", err)
	}

	secret := f.RefreshSecret()
	now := f.Clock.Now()

	t, err := token.NewRoot(id, spec.Session.ID(), family, hashOfSecret(secret), now, spec.Session.RefreshExpiry(now, policy))
	if err != nil {
		f.t.Fatalf("build refresh token: %v", err)
	}

	return t, secret
}

func (f *Factory) RefreshSecret() string {
	raw := make([]byte, 32)
	copy(raw, fmt.Sprintf("refresh-secret-%016x", f.IDs.n.Add(1)))

	return base64.RawURLEncoding.EncodeToString(raw)
}

func TokenHash(secret string) token.Hash {
	return hashOfSecret(secret)
}
