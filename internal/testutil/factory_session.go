package testutil

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/domain/session"
	"airlance.org/auth/internal/domain/token"
)

// SessionSpec describes a session. User is required: the link is explicit and no
// user is created implicitly.
type SessionSpec struct {
	User *identity.User
	// BindingSecret defaults to DefaultBindingSecret.
	BindingSecret string
	// DeviceName defaults to "test device".
	DeviceName string
	// AMR defaults to ["otp"].
	AMR []string
	// Policy defaults to session.DefaultPolicy().
	Policy *session.Policy
}

// Session starts a session at the factory clock time. Every call makes a new
// session, so one user gets independent device sessions.
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

// RefreshSpec describes the first refresh token of a session. Session is required.
type RefreshSpec struct {
	Session *session.Session
	// Policy defaults to session.DefaultPolicy().
	Policy *session.Policy
}

// hashOfSecret hashes a secret like the refresh secrets adapter does.
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

// RefreshToken builds the root token of a new family for spec.Session and returns
// it with its secret, which a client would hold.
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

// RefreshSecret returns a fresh, distinct, well-formed refresh secret.
func (f *Factory) RefreshSecret() string {
	raw := make([]byte, 32)
	copy(raw, fmt.Sprintf("refresh-secret-%016x", f.IDs.n.Add(1)))
	return base64.RawURLEncoding.EncodeToString(raw)
}

// TokenHash returns the stored hash of a secret.
func TokenHash(secret string) token.Hash { return hashOfSecret(secret) }
