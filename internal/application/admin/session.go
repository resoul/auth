package admin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/operator"
	dpasskey "go.airlance.org/auth/internal/domain/passkey"
)

// AuthenticateResult is the output of Authenticate.
type AuthenticateResult struct {
	Outcome  Outcome
	Actor    Actor
	Operator *operator.Operator
	// CSRFToken is the value the page must send in X-CSRF-Token.
	CSRFToken string
	ExpiresAt time.Time
}

// Authenticate resolves the cookie secret to a signed-in operator and records the use.
func (a *Auth) Authenticate(ctx context.Context, secret string) (AuthenticateResult, error) {
	hash, err := a.Secrets.HashTicketSecret(secret)
	if errors.Is(err, port.ErrInvalidTicketSecret) {
		return AuthenticateResult{Outcome: OutcomeUnauthenticated}, nil
	}

	if err != nil {
		return AuthenticateResult{}, fmt.Errorf("authenticate: %w", err)
	}

	now := a.Clock.Now()
	result := AuthenticateResult{Outcome: OutcomeUnauthenticated}

	err = a.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		sess, err := st.OperatorSessions.GetByHashForUpdate(ctx, hash)
		if errors.Is(err, port.ErrNotFound) {
			return nil
		}

		if err != nil {
			return fmt.Errorf("load operator session: %w", err)
		}

		if !sess.Active(now) {
			return nil
		}

		op, err := st.Operators.Get(ctx, sess.OperatorID())
		if err != nil {
			return fmt.Errorf("load operator: %w", err)
		}

		if op.Disabled() {
			return nil
		}

		if sess.Touch(now) {
			if err := st.OperatorSessions.Save(ctx, sess); err != nil {
				return fmt.Errorf("store operator session: %w", err)
			}
		}

		result = AuthenticateResult{
			Outcome: OutcomeOK, Actor: Actor{OperatorID: op.ID(), SessionID: sess.ID()}, Operator: op,
			CSRFToken: operator.CSRFToken(secret), ExpiresAt: sessionEnd(sess),
		}

		return nil
	})
	if err != nil {
		return AuthenticateResult{}, fmt.Errorf("authenticate: %w", err)
	}

	return result, nil
}

// Logout ends the session of the actor. A session that already ended is not an error.
func (a *Auth) Logout(ctx context.Context, actor Actor) error {
	now := a.Clock.Now()

	err := a.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		sess, err := st.OperatorSessions.GetForUpdate(ctx, actor.SessionID)
		if errors.Is(err, port.ErrNotFound) {
			return nil
		}

		if err != nil {
			return fmt.Errorf("load operator session: %w", err)
		}

		if sess.OperatorID() != actor.OperatorID {
			return nil
		}

		sess.Revoke(now)

		return st.OperatorSessions.Save(ctx, sess)
	})
	if err != nil {
		return fmt.Errorf("logout: %w", err)
	}

	return nil
}

// challengeDenied reports whether err means the challenge cannot be used.
func challengeDenied(err error) bool {
	return errors.Is(err, dpasskey.ErrChallengeExpired) || errors.Is(err, dpasskey.ErrChallengeUsed) || errors.Is(err, dpasskey.ErrChallengePurpose)
}
