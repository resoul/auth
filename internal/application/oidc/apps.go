package oidc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
	doidc "go.airlance.org/auth/internal/domain/oidc"
)

// Apps is what a person sees of the applications they connected, and how they take one back. It is always the caller's
// own: every statement is bound to the user's ID, which comes from the verified access token and never from the request.
//
// Revoking ends the chosen grants, with their refresh tokens, and tells each application's backend that this sign-in
// ended, so it closes its own session. It does not end the person's sign-in with the provider, other applications'
// grants, or anyone else's. It is also not a ban: while the sign-in lives, the application may start again and, being
// trusted, be given a new grant without a question. A lasting refusal is a decision about the application, not about
// one grant.
type Apps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
	// Metrics counts the grants taken back; nil counts nothing.
	Metrics port.OIDCMetrics
}

// NewApps checks the dependencies once, at assembly time.
func NewApps(a Apps) (*Apps, error) {
	if a.UnitOfWork == nil || a.Clock == nil {
		return nil, errors.New("new apps: all dependencies are required")
	}

	return &a, nil
}

// List returns the live grants of the user, applications by name and newest use first.
func (u *Apps) List(ctx context.Context, user identity.UserID) ([]port.AppGrant, error) {
	if user.IsZero() {
		return nil, nil
	}

	now := u.Clock.Now()

	var out []port.AppGrant

	err := u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		var err error

		out, err = st.OIDCApps.LiveGrantsOfUser(ctx, user, now)

		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list apps: %w", err)
	}

	return out, nil
}

// RevokeGrant ends one grant of the user. A grant that does not exist, is over, or belongs to someone else is not
// ended and not told apart: the answer is the same, so identifiers cannot be probed.
func (u *Apps) RevokeGrant(ctx context.Context, user identity.UserID, grantID string) error {
	if user.IsZero() {
		return nil
	}

	now := u.Clock.Now()
	n := 0

	err := u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		ended, clientID, err := st.OIDCApps.RevokeOwned(ctx, user, grantID, now)
		if err != nil || !ended {
			return err
		}

		n = 1

		return u.audit(ctx, st, now, user, clientID, "one")
	})
	if err != nil {
		return fmt.Errorf("revoke app grant: %w", err)
	}

	u.counted(n)

	return nil
}

// RevokeClient ends every live grant the user holds with one application, whatever sign-in it stands on.
func (u *Apps) RevokeClient(ctx context.Context, user identity.UserID, clientID string) error {
	if _, err := doidc.ParseClientID(clientID); err != nil || user.IsZero() {
		return nil
	}

	now := u.Clock.Now()
	ended := 0

	err := u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		n, err := st.OIDCApps.RevokeOwnedOfClient(ctx, user, clientID, now)
		if err != nil || n == 0 {
			return err
		}

		ended = n

		return u.audit(ctx, st, now, user, clientID, "client")
	})
	if err != nil {
		return fmt.Errorf("revoke app: %w", err)
	}

	u.counted(ended)

	return nil
}

// counted records the grants a person took back, once the change has committed.
func (u *Apps) counted(ended int) {
	if u.Metrics != nil && ended > 0 {
		u.Metrics.PermissionChange("grant_revoked_by_user", ended)
	}
}

func (u *Apps) audit(ctx context.Context, st port.Stores, now time.Time, user identity.UserID, clientID, scope string) error {
	if err := st.Audit.Record(ctx, port.AuditEvent{
		Type: port.AuditOIDCGrantEnded, Result: port.AuditSuccess, UserID: user, At: now,
		Fields: map[string]string{"client": clientID, "reason": "user_revoked", "scope": scope},
	}); err != nil {
		return fmt.Errorf("record audit event: %w", err)
	}

	return nil
}
