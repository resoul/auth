package oidc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"

	"go.airlance.org/auth/internal/application/port"
	appsession "go.airlance.org/auth/internal/application/session"
)

// Logout is RP-initiated logout: an application sends the browser here to end the shared sign-in. The first request
// only checks what was asked and returns what to show; a second one, confirmed by the person on the provider's own page,
// ends the sign-in. Nothing a client sends can end a sign-in by itself: a page that loads this address in an image would
// otherwise sign people out.
type Logout struct{ Deps }

// NewLogout checks the dependencies once, at assembly time.
func NewLogout(d Deps) (*Logout, error) {
	if err := d.validate("logout"); err != nil {
		return nil, err
	}

	return &Logout{d}, nil
}

// LogoutCommand is the input of Logout.
type LogoutCommand struct {
	// IDTokenHint is an ID token this provider issued for the client; it may have expired. ClientID names the client when
	// there is no hint, and must agree with it when there is one.
	IDTokenHint           string
	ClientID              string
	PostLogoutRedirectURI string
	State                 string
	// SSOSecret is the value of the OP session cookie, if the browser sent one.
	SSOSecret string
	// Confirm says the request is the submission of the confirmation page; ConfirmToken is what that page carried. The page
	// is the only place the token is shown, and it is derived from the cookie, which a page of another origin can neither
	// read nor send along: a trusted site that posts to this address by itself has no token to give.
	Confirm      bool
	ConfirmToken string
}

// confirmToken is the value the confirmation page carries for the browser that holds the cookie secret.
func confirmToken(secret string) string {
	sum := sha256.Sum256([]byte("airlance-oidc-logout-confirm\x00" + secret))
	return hex.EncodeToString(sum[:])
}

// Kinds of LogoutResult.
const (
	// LogoutConfirm asks the person to confirm: nothing was changed.
	LogoutConfirm = iota + 1
	// LogoutDone says the sign-in is ended, or there was none. Location is where to send the browser, or empty to
	// show a page that says so.
	LogoutDone
	// LogoutFailure shows an error on the provider; the browser is sent nowhere.
	LogoutFailure
)

// LogoutResult is the output of Logout.
type LogoutResult struct {
	Kind     int
	Location string
	Failure  *Failure
	// SignedOut says that a live shared sign-in was ended.
	SignedOut bool
	// ConfirmToken is what the confirmation page must carry back (set with LogoutConfirm).
	ConfirmToken string
}

// Execute validates the request and, when it is confirmed, ends the sign-in of the cookie: the OP session, its grants and
// refresh tokens, the device session it grew from, and a back-channel notice for every application that holds a grant on it.
func (u *Logout) Execute(ctx context.Context, cmd LogoutCommand) (LogoutResult, error) {
	redirect, f, err := u.check(ctx, cmd)
	if err != nil {
		return LogoutResult{}, err
	}

	if f != nil {
		return LogoutResult{Kind: LogoutFailure, Failure: f}, nil
	}

	if !cmd.Confirm {
		return LogoutResult{Kind: LogoutConfirm, ConfirmToken: confirmToken(cmd.SSOSecret)}, nil
	}

	if subtle.ConstantTimeCompare([]byte(cmd.ConfirmToken), []byte(confirmToken(cmd.SSOSecret))) != 1 {
		return LogoutResult{Kind: LogoutFailure, Failure: fail(ErrInvalidRequest, "The sign-out was not confirmed on this page.")}, nil
	}

	now := u.Clock.Now()

	result := LogoutResult{Kind: LogoutDone, Location: redirect}
	if cmd.SSOSecret == "" {
		return result, nil
	}

	hash, err := u.Secrets.HashOIDCSecret(cmd.SSOSecret)
	if errors.Is(err, port.ErrInvalidOIDCSecret) {
		return result, nil
	}

	if err != nil {
		return LogoutResult{}, fmt.Errorf("logout: hash sso cookie: %w", err)
	}

	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		op, err := st.OPSessions.GetBySecret(ctx, hash)
		if errors.Is(err, port.ErrNotFound) {
			return nil
		}

		if err != nil {
			return fmt.Errorf("load op session: %w", err)
		}

		if !op.RevokedAt.IsZero() {
			return nil // it was ended already: nothing to end again, nobody to tell again
		}

		if err := st.OPSessions.End(ctx, op.ID, now); err != nil {
			return fmt.Errorf("end op session: %w", err)
		}

		if op.DeviceSessionID != "" {
			if err := appsession.RevokeDeviceSession(ctx, st, op.UserID, op.DeviceSessionID, now); err != nil {
				return err
			}
		}

		result.SignedOut = true

		return st.Audit.Record(ctx, port.AuditEvent{Type: port.AuditOIDCLogout, Result: port.AuditSuccess, UserID: op.UserID, At: now, Fields: map[string]string{"scope": "current"}})
	})
	if err != nil {
		return LogoutResult{}, fmt.Errorf("logout: %w", err)
	}

	return result, nil
}

// check validates the parameters without changing anything and returns where the browser may be sent afterwards, with the
// state added, or "" when it may not be sent anywhere.
func (u *Logout) check(ctx context.Context, cmd LogoutCommand) (string, *Failure, error) {
	bad := func(text string) (string, *Failure, error) { return "", fail(ErrInvalidRequest, text), nil }
	if len(cmd.State) > maxParamLength {
		return bad("The state is too long.")
	}

	clientID := cmd.ClientID
	if cmd.IDTokenHint != "" {
		hint, err := u.Verifier.VerifyIDTokenHint(cmd.IDTokenHint)
		if errors.Is(err, port.ErrInvalidOIDCToken) {
			return bad("The ID token hint is not valid.")
		}

		if err != nil {
			return "", nil, fmt.Errorf("logout: %w", err)
		}

		if cmd.ClientID != "" && cmd.ClientID != hint.ClientID {
			return bad("The client does not match the ID token hint.")
		}

		clientID = hint.ClientID
	}

	if cmd.PostLogoutRedirectURI == "" {
		return "", nil, nil
	}
	// A return address is allowed only to a client that is known, active and registered it, exactly. Without a client
	// there is nobody to vouch for it.
	if clientID == "" {
		return bad("A return address needs the client or an ID token hint.")
	}

	var client interface {
		Active() bool
		AllowsPostLogoutRedirect(string) bool
	}

	err := u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		c, err := st.OIDCClients.Get(ctx, clientID)
		if errors.Is(err, port.ErrNotFound) {
			return nil
		}

		if err != nil {
			return fmt.Errorf("load client: %w", err)
		}

		client = c

		return nil
	})
	if err != nil {
		return "", nil, fmt.Errorf("logout: %w", err)
	}

	if client == nil || !client.Active() || !client.AllowsPostLogoutRedirect(cmd.PostLogoutRedirectURI) {
		return bad("The return address is not registered for this application.")
	}

	return redirectTo(cmd.PostLogoutRedirectURI, map[string]string{"state": cmd.State}), nil, nil
}
