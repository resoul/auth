package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.airlance.org/auth/internal/application/port"
	dsession "go.airlance.org/auth/internal/domain/session"
	"go.airlance.org/auth/internal/domain/token"
)

// RefreshDeps are the dependencies of Refresh.
type RefreshDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
	TokenIDs   port.RefreshTokenIDGenerator
	Secrets    port.RefreshSecrets
	// Metrics counts the reuse revocations.
	Metrics port.Metrics
	// Signer issues the access token. It signs before the transaction commits, so a
	// signing failure rolls the exchange back and the refresh token stays usable.
	Signer port.AccessSigner
	Policy dsession.Policy
}

// Refresh exchanges a refresh token for its only child under the strict rotation policy.
// Replaying a used token revokes the session.
type Refresh struct {
	RefreshDeps
}

// NewRefresh checks the dependencies once, at assembly time.
func NewRefresh(d RefreshDeps) (*Refresh, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.TokenIDs == nil || d.Secrets == nil || d.Signer == nil || d.Metrics == nil {
		return nil, errors.New("new refresh: all dependencies are required")
	}

	if err := d.Policy.Validate(); err != nil {
		return nil, fmt.Errorf("new refresh: %w", err)
	}

	return &Refresh{d}, nil
}

// RefreshCommand is the input of Refresh.
type RefreshCommand struct {
	RefreshSecret string
}

// RefreshResult is the output of Refresh. Session, Access, NewRefreshSecret and
// RefreshExpiresAt are set only for OutcomeOK.
type RefreshResult struct {
	Outcome          Outcome
	Reason           Reason
	Session          *dsession.Session
	Access           port.AccessToken
	NewRefreshSecret string
	RefreshExpiresAt time.Time
}

// Execute exchanges the token. Every refusal is OutcomeDenied. A reuse is committed
// (the session and its tokens are revoked) before the denial is returned; a
// technical failure rolls the exchange back and the token stays usable.
func (r *Refresh) Execute(ctx context.Context, cmd RefreshCommand) (RefreshResult, error) {
	hash, err := r.Secrets.HashRefreshSecret(cmd.RefreshSecret)
	if errors.Is(err, port.ErrInvalidRefreshSecret) {
		return RefreshResult{Outcome: OutcomeDenied, Reason: ReasonMalformed}, nil
	}

	if err != nil {
		return RefreshResult{}, fmt.Errorf("refresh: hash secret: %w", err)
	}
	// Generated up front: a failure here writes nothing.
	childID, err := r.TokenIDs.NewRefreshTokenID()
	if err != nil {
		return RefreshResult{}, fmt.Errorf("refresh: %w", err)
	}

	newSecret, newHash, err := r.Secrets.NewRefreshSecret()
	if err != nil {
		return RefreshResult{}, fmt.Errorf("refresh: %w", err)
	}

	now := r.Clock.Now()

	var result RefreshResult

	err = r.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		found, err := st.Tokens.FindByHash(ctx, hash)
		if errors.Is(err, port.ErrNotFound) {
			result = denied(ReasonUnknownToken)
			return nil
		}

		if err != nil {
			return fmt.Errorf("find token: %w", err)
		}

		// The session is locked before the token, like sign-out does, so a revoked
		// session cannot receive new tokens.
		sess, err := st.Sessions.GetForUpdate(ctx, found.SessionID())
		if errors.Is(err, port.ErrNotFound) {
			result = denied(ReasonUnknownSession)
			return nil
		}

		if err != nil {
			return fmt.Errorf("load session: %w", err)
		}

		tok, err := st.Tokens.GetForUpdate(ctx, found.ID())
		if errors.Is(err, port.ErrNotFound) {
			result = denied(ReasonUnknownToken)
			return nil
		}

		if err != nil {
			return fmt.Errorf("load token: %w", err)
		}

		if !sess.Active(now) {
			result = denied(ReasonSessionInactive)
			return nil
		}

		child, err := tok.Rotate(now, childID, newHash, sess.RefreshExpiry(now, r.Policy))
		switch {
		case errors.Is(err, token.ErrReused):
			// Replay of an exchanged token: revoke, commit, and only then refuse.
			sess.Revoke(now)

			if err := st.Sessions.Save(ctx, sess); err != nil {
				return fmt.Errorf("revoke session after reuse: %w", err)
			}

			if err := st.Tokens.RevokeBySession(ctx, sess.ID(), now); err != nil {
				return fmt.Errorf("revoke tokens after reuse: %w", err)
			}

			if err := st.Audit.Record(ctx, port.AuditEvent{
				Type: port.AuditRefreshReuse, Result: port.AuditDenied, UserID: sess.UserID(), SessionID: sess.ID(), At: now,
				Fields: map[string]string{"reason": "token_reused"},
			}); err != nil {
				return fmt.Errorf("record audit event: %w", err)
			}

			result = denied(ReasonTokenReused)

			return nil
		case errors.Is(err, token.ErrRevoked):
			result = denied(ReasonTokenRevoked)
			return nil
		case errors.Is(err, token.ErrExpired):
			result = denied(ReasonTokenExpired)
			return nil
		case err != nil:
			return fmt.Errorf("rotate token: %w", err)
		}

		// A successful refresh proves the device again, so recognition lasts as long as
		// the device is in use. A revoked or missing record is not restored and does not
		// fail the exchange.
		if err := st.Recognized.Extend(ctx, sess.UserID(), sess.Binding(), now); err != nil && !errors.Is(err, port.ErrNotFound) {
			return fmt.Errorf("extend recognition: %w", err)
		}

		if err := sess.Touch(now, r.Policy); err != nil {
			return fmt.Errorf("touch session: %w", err)
		}
		// Signed before anything is committed: a signer failure rolls everything back.
		access, err := r.Signer.SignAccess(port.AccessClaims{
			UserID: sess.UserID(), SessionID: sess.ID(), AuthTime: sess.AuthTime(), AMR: sess.AMR(),
		})
		if err != nil {
			return fmt.Errorf("sign access token: %w", err)
		}

		if err := st.Tokens.Save(ctx, tok); err != nil {
			return fmt.Errorf("store used token: %w", err)
		}

		if err := st.Tokens.Create(ctx, child); err != nil {
			return fmt.Errorf("store child token: %w", err)
		}

		if err := st.Sessions.Save(ctx, sess); err != nil {
			return fmt.Errorf("store session: %w", err)
		}

		result = RefreshResult{
			Outcome: OutcomeOK, Session: sess, Access: access, NewRefreshSecret: newSecret, RefreshExpiresAt: child.ExpiresAt(),
		}

		return nil
	})
	if err != nil {
		return RefreshResult{}, fmt.Errorf("refresh: %w", err)
	}
	// Counted after the commit: a rolled back revocation did not happen.
	if result.Reason == ReasonTokenReused {
		r.Metrics.RefreshReuseDetected()
	}

	return result, nil
}

func denied(reason Reason) RefreshResult {
	return RefreshResult{Outcome: OutcomeDenied, Reason: reason}
}
