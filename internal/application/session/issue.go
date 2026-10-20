package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
	dsession "go.airlance.org/auth/internal/domain/session"
	"go.airlance.org/auth/internal/domain/token"
)

// IssuerDeps are the dependencies of Issuer.
type IssuerDeps struct {
	SessionIDs port.SessionIDGenerator
	TokenIDs   port.RefreshTokenIDGenerator
	Secrets    port.RefreshSecrets
	Policy     dsession.Policy
}

// Issuer starts a session with the first refresh token of a new family. It runs
// inside the caller's transaction so a successful verify can create the user, the
// session and the tokens atomically.
type Issuer struct {
	IssuerDeps
}

// NewIssuer checks the dependencies once, at assembly time.
func NewIssuer(d IssuerDeps) (*Issuer, error) {
	if d.SessionIDs == nil || d.TokenIDs == nil || d.Secrets == nil {
		return nil, errors.New("new issuer: all dependencies are required")
	}

	if err := d.Policy.Validate(); err != nil {
		return nil, fmt.Errorf("new issuer: %w", err)
	}

	return &Issuer{d}, nil
}

// IssueParams describes the login being recorded.
type IssueParams struct {
	UserID     identity.UserID
	Binding    identity.BindingHash
	AMR        []string
	AuthTime   time.Time
	DeviceName string
}

// Issued is a new session with the secret of its first refresh token. The secret
// exists only here; the store keeps its hash.
type Issued struct {
	Session          *dsession.Session
	RefreshSecret    string
	RefreshExpiresAt time.Time
}

// Issue creates the session and the root token of a new family in st.
func (i *Issuer) Issue(ctx context.Context, st port.Stores, now time.Time, p IssueParams) (Issued, error) {
	sessionID, err := i.SessionIDs.NewSessionID()
	if err != nil {
		return Issued{}, fmt.Errorf("issue session: %w", err)
	}

	tokenID, err := i.TokenIDs.NewRefreshTokenID()
	if err != nil {
		return Issued{}, fmt.Errorf("issue session: %w", err)
	}

	familyID, err := i.TokenIDs.NewFamilyID()
	if err != nil {
		return Issued{}, fmt.Errorf("issue session: %w", err)
	}

	secret, hash, err := i.Secrets.NewRefreshSecret()
	if err != nil {
		return Issued{}, fmt.Errorf("issue session: %w", err)
	}

	sess, err := dsession.New(dsession.NewParams{
		ID: sessionID, UserID: p.UserID, Binding: p.Binding, AMR: p.AMR,
		AuthTime: p.AuthTime, DeviceName: p.DeviceName,
	}, now, i.Policy)
	if err != nil {
		return Issued{}, fmt.Errorf("issue session: %w", err)
	}

	expiresAt := sess.RefreshExpiry(now, i.Policy)

	root, err := token.NewRoot(tokenID, sess.ID(), familyID, hash, now, expiresAt)
	if err != nil {
		return Issued{}, fmt.Errorf("issue session: %w", err)
	}

	if err := st.Sessions.Create(ctx, sess); err != nil {
		return Issued{}, fmt.Errorf("store session: %w", err)
	}

	if err := st.Tokens.Create(ctx, root); err != nil {
		return Issued{}, fmt.Errorf("store refresh token: %w", err)
	}

	return Issued{Session: sess, RefreshSecret: secret, RefreshExpiresAt: expiresAt}, nil
}
