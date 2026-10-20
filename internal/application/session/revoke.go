package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
	dsession "go.airlance.org/auth/internal/domain/session"
)

// RevokeDeps are the dependencies of RevokeSession and RevokeAll.
type RevokeDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
}

func (d RevokeDeps) validate(name string) error {
	if d.UnitOfWork == nil || d.Clock == nil {
		return fmt.Errorf("new %s: all dependencies are required", name)
	}

	return nil
}

// RevokeSession ends one session of the acting user.
type RevokeSession struct {
	RevokeDeps
}

// NewRevokeSession checks the dependencies once, at assembly time.
func NewRevokeSession(d RevokeDeps) (*RevokeSession, error) {
	if err := d.validate("revoke session"); err != nil {
		return nil, err
	}

	return &RevokeSession{d}, nil
}

// RevokeSessionCommand is the input of RevokeSession. ActorUserID comes from the
// verified authentication, never from the request body.
type RevokeSessionCommand struct {
	ActorUserID identity.UserID
	SessionID   string
}

// RevokeResult is the output of the revoke use cases. A session that is missing and
// one that belongs to someone else give the same denial.
type RevokeResult struct {
	Outcome Outcome
}

// Execute revokes the session and its refresh tokens, atomically. Revoking an
// already revoked session succeeds and keeps the first time.
func (u *RevokeSession) Execute(ctx context.Context, cmd RevokeSessionCommand) (RevokeResult, error) {
	id, err := dsession.ParseID(cmd.SessionID)
	if err != nil || cmd.ActorUserID.IsZero() {
		return RevokeResult{Outcome: OutcomeDenied}, nil
	}

	now := u.Clock.Now()

	result := RevokeResult{Outcome: OutcomeDenied}

	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		sess, err := st.Sessions.GetForUpdate(ctx, id)
		if errors.Is(err, port.ErrNotFound) {
			return nil
		}

		if err != nil {
			return fmt.Errorf("load session: %w", err)
		}

		if sess.UserID() != cmd.ActorUserID {
			return nil
		}

		if err := revokeSession(ctx, st, sess, now, map[string]string{"scope": "one"}); err != nil {
			return err
		}

		result = RevokeResult{Outcome: OutcomeOK}

		return nil
	})
	if err != nil {
		return RevokeResult{}, fmt.Errorf("revoke session: %w", err)
	}

	return result, nil
}

// revokeSession ends one session and its refresh tokens and records the event. The
// recognition of the device is not touched: signing a device out keeps it recognized.
func revokeSession(ctx context.Context, st port.Stores, sess *dsession.Session, now time.Time, fields map[string]string) error {
	sess.Revoke(now)

	if err := st.Sessions.Save(ctx, sess); err != nil {
		return fmt.Errorf("store session: %w", err)
	}

	if err := st.Tokens.RevokeBySession(ctx, sess.ID(), now); err != nil {
		return fmt.Errorf("revoke tokens: %w", err)
	}

	if err := st.Audit.Record(ctx, port.AuditEvent{
		Type: port.AuditSessionRevoked, Result: port.AuditSuccess, UserID: sess.UserID(), SessionID: sess.ID(), At: now, Fields: fields,
	}); err != nil {
		return fmt.Errorf("record audit event: %w", err)
	}

	return nil
}

// revokeEverything ends every session, token, ticket and recognition record of the user, and the shared sign-in of the
// OpenID Provider with every grant and refresh token held on it: signing out everywhere forgets every device and every
// application. A recovery or a block comes here too, so nothing issued from the old proof survives it.
func revokeEverything(ctx context.Context, st port.Stores, userID identity.UserID, now time.Time) error {
	if err := st.OPSessions.RevokeAllForUser(ctx, userID, now); err != nil {
		return fmt.Errorf("revoke op sessions: %w", err)
	}

	if err := st.Sessions.RevokeAllForUser(ctx, userID, now); err != nil {
		return fmt.Errorf("revoke sessions: %w", err)
	}

	if err := st.Tokens.RevokeAllForUser(ctx, userID, now); err != nil {
		return fmt.Errorf("revoke tokens: %w", err)
	}

	if err := st.Recognized.RevokeAll(ctx, userID, now); err != nil {
		return fmt.Errorf("revoke recognition: %w", err)
	}

	// A ticket issued before, a recovery one above all, must not reopen what was just closed.
	if err := st.Tickets.RevokeAllForUser(ctx, userID, dsession.ID{}, now); err != nil {
		return fmt.Errorf("revoke tickets: %w", err)
	}

	if err := st.Audit.Record(ctx, port.AuditEvent{
		Type: port.AuditAllSessionsRevoked, Result: port.AuditSuccess, UserID: userID, At: now,
		Fields: map[string]string{"scope": "all"},
	}); err != nil {
		return fmt.Errorf("record audit event: %w", err)
	}

	return nil
}

// RevokeAll ends every session of the acting user and forgets every recognized device.
type RevokeAll struct {
	RevokeDeps
}

// NewRevokeAll checks the dependencies once, at assembly time.
func NewRevokeAll(d RevokeDeps) (*RevokeAll, error) {
	if err := d.validate("revoke all"); err != nil {
		return nil, err
	}

	return &RevokeAll{d}, nil
}

// RevokeAllCommand is the input of RevokeAll.
type RevokeAllCommand struct {
	ActorUserID identity.UserID
}

// Execute revokes all sessions, tokens and recognition records of the user, atomically.
func (u *RevokeAll) Execute(ctx context.Context, cmd RevokeAllCommand) (RevokeResult, error) {
	if cmd.ActorUserID.IsZero() {
		return RevokeResult{Outcome: OutcomeDenied}, nil
	}

	now := u.Clock.Now()

	err := u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		return revokeEverything(ctx, st, cmd.ActorUserID, now)
	})
	if err != nil {
		return RevokeResult{}, fmt.Errorf("revoke all sessions: %w", err)
	}

	return RevokeResult{Outcome: OutcomeOK}, nil
}

// RevokeOthers ends every session, refresh token and ticket of the user except the session keep, inside the
// caller's transaction. A change that cuts someone off from the account (a deleted key, a moved
// address) must not leave their other sessions alive; the one that made the change stays, since its
// owner just proved a key. reason is the audit code of the change.
func RevokeOthers(ctx context.Context, st port.Stores, userID identity.UserID, keep dsession.ID, now time.Time, reason string) error {
	// The shared sign-ins go with the other devices; the one that grew from the kept session stays, as that session does.
	keepID := ""
	if !keep.IsZero() {
		keepID = keep.String()
	}

	if err := st.OPSessions.RevokeOthersForUser(ctx, userID, keepID, now); err != nil {
		return fmt.Errorf("revoke other op sessions: %w", err)
	}

	if err := st.Sessions.RevokeOthersForUser(ctx, userID, keep, now); err != nil {
		return fmt.Errorf("revoke other sessions: %w", err)
	}

	if err := st.Tokens.RevokeOthersForUser(ctx, userID, keep, now); err != nil {
		return fmt.Errorf("revoke other tokens: %w", err)
	}

	// Tickets of the other devices go too; the step-up tickets of the kept session stay with it.
	if err := st.Tickets.RevokeAllForUser(ctx, userID, keep, now); err != nil {
		return fmt.Errorf("revoke tickets: %w", err)
	}

	if err := st.Audit.Record(ctx, port.AuditEvent{
		Type: port.AuditAllSessionsRevoked, Result: port.AuditSuccess, UserID: userID, SessionID: keep, At: now,
		Fields: map[string]string{"scope": "others", "reason": reason},
	}); err != nil {
		return fmt.Errorf("record audit event: %w", err)
	}

	return nil
}

// RevokeEverything ends every session, token, ticket and recognition record of the user inside the
// caller's transaction. A recovery code proves that keys were lost, so sessions opened with
// them must not outlive the recovery.
func RevokeEverything(ctx context.Context, st port.Stores, userID identity.UserID, now time.Time) error {
	return revokeEverything(ctx, st, userID, now)
}

// RevokeDeviceSession ends one session of the user, with its refresh tokens, inside the caller's transaction. It is for the
// sign-in of the OpenID Provider, which grew from such a session and takes it along when it ends. A session that is gone, or
// is another user's, is left alone and is not an error.
func RevokeDeviceSession(ctx context.Context, st port.Stores, userID identity.UserID, id string, now time.Time) error {
	sid, err := dsession.ParseID(id)
	if err != nil {
		return nil
	}

	sess, err := st.Sessions.GetForUpdate(ctx, sid)
	if errors.Is(err, port.ErrNotFound) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("load session: %w", err)
	}

	if sess.UserID() != userID || !sess.RevokedAt().IsZero() {
		return nil
	}

	return revokeSession(ctx, st, sess, now, map[string]string{"scope": "one"})
}
