package session

import (
	"context"
	"errors"
	"fmt"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
	dsession "go.airlance.org/auth/internal/domain/session"
)

// Actor is who a protected request acts as: the user and the device session of the access
// token. It is produced only by Authenticator; handlers never build it from a request.
type Actor struct {
	UserID    identity.UserID
	SessionID dsession.ID
}

// AuthenticateDeps are the dependencies of Authenticator.
type AuthenticateDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
	Verifier   port.AccessVerifier
}

// Authenticator turns an access token into an Actor. The signature and claims are not
// enough: a revoked or expired session must stop working before the token's own expiry, so
// the session is read from the store on every check.
type Authenticator struct {
	AuthenticateDeps
}

// NewAuthenticator checks the dependencies once, at assembly time.
func NewAuthenticator(d AuthenticateDeps) (*Authenticator, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.Verifier == nil {
		return nil, errors.New("new authenticator: all dependencies are required")
	}

	return &Authenticator{d}, nil
}

// AuthResult is the output of Authenticator. Actor is set only for OutcomeOK.
type AuthResult struct {
	Outcome Outcome
	Reason  Reason
	Actor   Actor
}

// Execute verifies the token and the state of its session. Every refusal is
// OutcomeDenied and looks alike to clients.
func (a *Authenticator) Execute(ctx context.Context, accessToken string) (AuthResult, error) {
	claims, err := a.Verifier.VerifyAccess(accessToken)
	if errors.Is(err, port.ErrInvalidAccessToken) {
		return AuthResult{Outcome: OutcomeDenied, Reason: ReasonInvalidToken}, nil
	}

	if err != nil {
		return AuthResult{}, fmt.Errorf("authenticate: %w", err)
	}

	now := a.Clock.Now()

	result := AuthResult{Outcome: OutcomeDenied, Reason: ReasonUnknownSession}

	err = a.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		sess, err := st.Sessions.Get(ctx, claims.SessionID)
		if errors.Is(err, port.ErrNotFound) {
			return nil
		}

		if err != nil {
			return fmt.Errorf("load session: %w", err)
		}

		switch {
		case sess.UserID() != claims.UserID:
			// A token that names a session of another user is forged or confused.
		case !sess.Active(now):
			result.Reason = ReasonSessionInactive
		default:
			result = AuthResult{Outcome: OutcomeOK, Actor: Actor{UserID: sess.UserID(), SessionID: sess.ID()}}
		}

		return nil
	})
	if err != nil {
		return AuthResult{}, fmt.Errorf("authenticate: %w", err)
	}

	return result, nil
}
