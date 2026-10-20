package session

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"go.airlance.org/auth/internal/application/port"
)

// SignOutScope says which sessions a sign-out ends.
type SignOutScope string

// Scopes of a sign-out.
const (
	ScopeCurrent SignOutScope = "current"
	ScopeAll     SignOutScope = "all"
)

// SignOut ends the acting session or all sessions of the user.
type SignOut struct {
	RevokeDeps
}

// NewSignOut checks the dependencies once, at assembly time.
func NewSignOut(d RevokeDeps) (*SignOut, error) {
	if err := d.validate("sign out"); err != nil {
		return nil, err
	}

	return &SignOut{d}, nil
}

// SignOutCommand is the input of SignOut. Actor comes from Authenticator.
type SignOutCommand struct {
	Actor Actor
	Scope SignOutScope
	// ForgetClient also ends the recognition of this device. It is implied by ScopeAll.
	ForgetClient bool
}

// Execute signs out. The current scope ends the acting session and its refresh tokens and
// keeps the device recognized unless ForgetClient is set; the all scope ends every session
// and every recognition record of the user. Signing out an already ended session succeeds.
func (u *SignOut) Execute(ctx context.Context, cmd SignOutCommand) (RevokeResult, error) {
	if cmd.Actor.UserID.IsZero() || (cmd.Scope != ScopeCurrent && cmd.Scope != ScopeAll) {
		return RevokeResult{Outcome: OutcomeDenied}, nil
	}

	now := u.Clock.Now()

	result := RevokeResult{Outcome: OutcomeDenied}

	err := u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		sess, err := st.Sessions.GetForUpdate(ctx, cmd.Actor.SessionID)
		if errors.Is(err, port.ErrNotFound) {
			return nil
		}

		if err != nil {
			return fmt.Errorf("load session: %w", err)
		}

		if sess.UserID() != cmd.Actor.UserID {
			return nil
		}

		if cmd.Scope == ScopeAll {
			if err := revokeEverything(ctx, st, cmd.Actor.UserID, now); err != nil {
				return err
			}

			result = RevokeResult{Outcome: OutcomeOK}

			return nil
		}

		fields := map[string]string{"scope": string(ScopeCurrent), "forget_client": strconv.FormatBool(cmd.ForgetClient)}
		if err := revokeSession(ctx, st, sess, now, fields); err != nil {
			return err
		}

		if cmd.ForgetClient {
			if err := st.Recognized.Revoke(ctx, sess.UserID(), sess.Binding(), now); err != nil {
				return fmt.Errorf("revoke recognition: %w", err)
			}
		}

		result = RevokeResult{Outcome: OutcomeOK}

		return nil
	})
	if err != nil {
		return RevokeResult{}, fmt.Errorf("sign out: %w", err)
	}

	return result, nil
}
