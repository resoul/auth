package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/identity"
	dsession "airlance.org/auth/internal/domain/session"
)

// MaxListedSessions bounds the session list of one user.
const MaxListedSessions = 100

// ReadDeps are the dependencies of the read use cases.
type ReadDeps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
}

func (d ReadDeps) validate(name string) error {
	if d.UnitOfWork == nil || d.Clock == nil {
		return fmt.Errorf("new %s: all dependencies are required", name)
	}
	return nil
}

// Me returns the acting user and the session of the access token.
type Me struct {
	ReadDeps
}

// NewMe checks the dependencies once, at assembly time.
func NewMe(d ReadDeps) (*Me, error) {
	if err := d.validate("me"); err != nil {
		return nil, err
	}
	return &Me{d}, nil
}

// MeResult is the output of Me. User and Session are set only for OutcomeOK.
type MeResult struct {
	Outcome Outcome
	User    *identity.User
	Session *dsession.Session
}

// Execute reads the user and the current session. The session is checked again, so a
// session revoked since the access check gets nothing.
func (u *Me) Execute(ctx context.Context, actor Actor) (MeResult, error) {
	now := u.Clock.Now()
	result := MeResult{Outcome: OutcomeDenied}
	err := u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		sess, ok, err := ownActiveSession(ctx, st, actor, now)
		if err != nil || !ok {
			return err
		}
		user, err := st.Users.Get(ctx, actor.UserID)
		if errors.Is(err, port.ErrNotFound) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("load user: %w", err)
		}
		result = MeResult{Outcome: OutcomeOK, User: user, Session: sess}
		return nil
	})
	if err != nil {
		return MeResult{}, fmt.Errorf("me: %w", err)
	}
	return result, nil
}

// ListSessions returns the acting user's active sessions.
type ListSessions struct {
	ReadDeps
}

// NewListSessions checks the dependencies once, at assembly time.
func NewListSessions(d ReadDeps) (*ListSessions, error) {
	if err := d.validate("list sessions"); err != nil {
		return nil, err
	}
	return &ListSessions{d}, nil
}

// ListResult is the output of ListSessions. Sessions is set only for OutcomeOK.
type ListResult struct {
	Outcome  Outcome
	Sessions []*dsession.Session
}

// Execute lists the user's active sessions, the current one included, most recently
// active first. Only the actor's own sessions are ever read.
func (u *ListSessions) Execute(ctx context.Context, actor Actor) (ListResult, error) {
	now := u.Clock.Now()
	result := ListResult{Outcome: OutcomeDenied}
	err := u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if _, ok, err := ownActiveSession(ctx, st, actor, now); err != nil || !ok {
			return err
		}
		list, err := st.Sessions.ListActive(ctx, actor.UserID, now, MaxListedSessions)
		if err != nil {
			return fmt.Errorf("list sessions: %w", err)
		}
		result = ListResult{Outcome: OutcomeOK, Sessions: list}
		return nil
	})
	if err != nil {
		return ListResult{}, fmt.Errorf("list sessions: %w", err)
	}
	return result, nil
}

// ownActiveSession loads the actor's session and reports whether it still belongs to the
// user and is active.
func ownActiveSession(ctx context.Context, st port.Stores, actor Actor, now time.Time) (*dsession.Session, bool, error) {
	if actor.UserID.IsZero() {
		return nil, false, nil
	}
	sess, err := st.Sessions.Get(ctx, actor.SessionID)
	if errors.Is(err, port.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("load session: %w", err)
	}
	if sess.UserID() != actor.UserID || !sess.Active(now) {
		return nil, false, nil
	}
	return sess, true, nil
}

// ActiveSession loads the actor's session and reports whether it still belongs to the user and
// is active. Use cases of other packages call it inside their transaction, so a session revoked
// since the access check gets nothing.
func ActiveSession(ctx context.Context, st port.Stores, actor Actor, now time.Time) (*dsession.Session, bool, error) {
	return ownActiveSession(ctx, st, actor, now)
}
