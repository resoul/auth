package session_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"airlance.org/auth/internal/application/port"
	appsession "airlance.org/auth/internal/application/session"
	"airlance.org/auth/internal/domain/session"
	"airlance.org/auth/internal/testutil"
)

func (e *env) access(sess *session.Session) string {
	e.t.Helper()
	tok, err := e.signer.SignAccess(port.AccessClaims{UserID: sess.UserID(), SessionID: sess.ID(), AuthTime: sess.AuthTime(), AMR: sess.AMR()})
	if err != nil {
		e.t.Fatal(err)
	}
	return tok.Value
}

func (e *env) authenticator() *appsession.Authenticator {
	e.t.Helper()
	a, err := appsession.NewAuthenticator(appsession.AuthenticateDeps{UnitOfWork: e.faults, Clock: e.clock, Verifier: e.verify})
	if err != nil {
		e.t.Fatal(err)
	}
	return a
}

func (e *env) authenticate(token string) appsession.AuthResult {
	e.t.Helper()
	res, err := e.authenticator().Execute(context.Background(), token)
	if err != nil {
		e.t.Fatalf("authenticate: %v", err)
	}
	return res
}

func (e *env) actor(issued appsession.Issued) appsession.Actor {
	return appsession.Actor{UserID: issued.Session.UserID(), SessionID: issued.Session.ID()}
}

func TestAuthenticateAcceptsATokenOfALiveSession(t *testing.T) {
	e := newEnv(t)
	issued, user := e.login("alice@example.test")
	res := e.authenticate(e.access(issued.Session))
	if res.Outcome != appsession.OutcomeOK || res.Actor.UserID != user.ID() || res.Actor.SessionID != issued.Session.ID() {
		t.Errorf("result = %+v", res)
	}
}

func TestAuthenticateStopsAtOnceWhenTheSessionEnds(t *testing.T) {
	e := newEnv(t)
	issued, user := e.login("alice@example.test")
	token := e.access(issued.Session)
	if res := e.authenticate(token); res.Outcome != appsession.OutcomeOK {
		t.Fatalf("before the revocation = %+v", res)
	}
	if res, err := e.revoke.Execute(context.Background(), appsession.RevokeSessionCommand{ActorUserID: user.ID(), SessionID: issued.Session.ID().String()}); err != nil || res.Outcome != appsession.OutcomeOK {
		t.Fatal(res, err)
	}
	// The token is still signed and unexpired, yet the session is gone.
	if res := e.authenticate(token); res.Outcome != appsession.OutcomeDenied || res.Reason != appsession.ReasonSessionInactive {
		t.Errorf("after the revocation = %+v", res)
	}
}

func TestAuthenticateStopsWhenTheSessionExpires(t *testing.T) {
	e := newEnv(t)
	issued, _ := e.login("alice@example.test")
	// A token that outlives the idle limit: sign it late enough that only the session is stale.
	e.clock.Advance(31 * day)
	if res := e.authenticate(e.access(issued.Session)); res.Outcome != appsession.OutcomeDenied || res.Reason != appsession.ReasonSessionInactive {
		t.Errorf("an idle-expired session authenticated: %+v", res)
	}
}

func TestAuthenticateRefusesWhatIsNotAValidTokenForARealSession(t *testing.T) {
	e := newEnv(t)
	issued, _ := e.login("alice@example.test")
	_, mallory := e.login("mallory@example.test")
	ghost := e.factory.Session(testutil.SessionSpec{User: mallory}) // never stored

	expired := e.access(issued.Session)
	e.clock.Advance(time.Hour)
	forged, err := e.signer.SignAccess(port.AccessClaims{UserID: mallory.ID(), SessionID: issued.Session.ID(), AuthTime: t0, AMR: []string{"otp"}})
	if err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct {
		token  string
		reason appsession.Reason
	}{
		"empty":                         {"", appsession.ReasonInvalidToken},
		"garbage":                       {"not.a.token", appsession.ReasonInvalidToken},
		"expired":                       {expired, appsession.ReasonInvalidToken},
		"a session of another user":     {forged.Value, appsession.ReasonUnknownSession},
		"a session that does not exist": {e.access(ghost), appsession.ReasonUnknownSession},
		"a refresh secret as a bearer":  {issued.RefreshSecret, appsession.ReasonInvalidToken},
	} {
		t.Run(name, func(t *testing.T) {
			if res := e.authenticate(tc.token); res.Outcome != appsession.OutcomeDenied || res.Reason != tc.reason || res.Actor != (appsession.Actor{}) {
				t.Errorf("result = %+v, want denied (%s) without an actor", res, tc.reason)
			}
		})
	}
}

func TestAuthenticateReportsTechnicalFailures(t *testing.T) {
	e := newEnv(t)
	issued, _ := e.login("alice@example.test")
	token := e.access(issued.Session)
	e.faults.wrap = func(s port.Stores) port.Stores { s.Sessions = failingSessionGet{s.Sessions}; return s }
	if _, err := e.authenticator().Execute(context.Background(), token); !errors.Is(err, errBoom) {
		t.Errorf("error = %v, want the store failure rather than a denial", err)
	}
	e.faults.wrap = nil
	if res := e.authenticate(token); res.Outcome != appsession.OutcomeOK {
		t.Errorf("a failed check changed the session: %+v", res)
	}
}

type failingSessionGet struct{ port.SessionRepository }

func (failingSessionGet) Get(context.Context, session.ID) (*session.Session, error) {
	return nil, errBoom
}

func TestNewAuthenticatorRequiresDependencies(t *testing.T) {
	e := newEnv(t)
	for name, d := range map[string]appsession.AuthenticateDeps{
		"unit of work": {Clock: e.clock, Verifier: e.verify},
		"clock":        {UnitOfWork: e.store, Verifier: e.verify},
		"verifier":     {UnitOfWork: e.store, Clock: e.clock},
	} {
		if _, err := appsession.NewAuthenticator(d); err == nil {
			t.Errorf("missing %s accepted", name)
		}
	}
}

func (e *env) me() *appsession.Me {
	e.t.Helper()
	u, err := appsession.NewMe(appsession.ReadDeps{UnitOfWork: e.faults, Clock: e.clock})
	if err != nil {
		e.t.Fatal(err)
	}
	return u
}

func (e *env) list() *appsession.ListSessions {
	e.t.Helper()
	u, err := appsession.NewListSessions(appsession.ReadDeps{UnitOfWork: e.faults, Clock: e.clock})
	if err != nil {
		e.t.Fatal(err)
	}
	return u
}

func TestMeReturnsTheUserAndTheCurrentSession(t *testing.T) {
	e := newEnv(t)
	issued, user := e.login("alice@example.test")
	res, err := e.me().Execute(context.Background(), e.actor(issued))
	if err != nil || res.Outcome != appsession.OutcomeOK || res.User.ID() != user.ID() || res.User.Email() != user.Email() || res.Session.ID() != issued.Session.ID() {
		t.Fatalf("me = %+v, %v", res, err)
	}
}

func TestMeAndListRefuseAnEndedOrForeignActor(t *testing.T) {
	e := newEnv(t)
	issued, user := e.login("alice@example.test")
	_, mallory := e.login("mallory@example.test")
	actor := e.actor(issued)
	if _, err := e.revoke.Execute(context.Background(), appsession.RevokeSessionCommand{ActorUserID: user.ID(), SessionID: issued.Session.ID().String()}); err != nil {
		t.Fatal(err)
	}
	foreign := appsession.Actor{UserID: mallory.ID(), SessionID: issued.Session.ID()}

	for name, a := range map[string]appsession.Actor{"revoked session": actor, "someone else's session": foreign, "no actor": {}} {
		if res, err := e.me().Execute(context.Background(), a); err != nil || res.Outcome != appsession.OutcomeDenied || res.User != nil {
			t.Errorf("me for %s = %+v, %v", name, res, err)
		}
		if res, err := e.list().Execute(context.Background(), a); err != nil || res.Outcome != appsession.OutcomeDenied || res.Sessions != nil {
			t.Errorf("list for %s = %+v, %v", name, res, err)
		}
	}
}

func TestListShowsOnlyTheActorsActiveSessions(t *testing.T) {
	e := newEnv(t)
	laptop, user := e.login("alice@example.test")
	e.clock.Advance(time.Hour)
	phone := e.loginAgain(user)
	e.login("bob@example.test")
	e.clock.Advance(time.Hour)
	tablet := e.loginAgain(user)
	if _, err := e.revoke.Execute(context.Background(), appsession.RevokeSessionCommand{ActorUserID: user.ID(), SessionID: tablet.Session.ID().String()}); err != nil {
		t.Fatal(err)
	}

	res, err := e.list().Execute(context.Background(), e.actor(laptop))
	if err != nil || res.Outcome != appsession.OutcomeOK {
		t.Fatalf("list = %+v, %v", res, err)
	}
	var got []session.ID
	for _, s := range res.Sessions {
		got = append(got, s.ID())
		if s.UserID() != user.ID() {
			t.Errorf("session %s belongs to another user", s.ID())
		}
	}
	if len(got) != 2 || got[0] != phone.Session.ID() || got[1] != laptop.Session.ID() {
		t.Errorf("sessions = %v, want the phone then the laptop: the revoked tablet and Bob's are not listed", got)
	}
}

func TestNewReadUseCasesRequireDependencies(t *testing.T) {
	if _, err := appsession.NewMe(appsession.ReadDeps{}); err == nil {
		t.Error("NewMe accepted nothing")
	}
	if _, err := appsession.NewListSessions(appsession.ReadDeps{}); err == nil {
		t.Error("NewListSessions accepted nothing")
	}
	if _, err := appsession.NewSignOut(appsession.RevokeDeps{}); err == nil {
		t.Error("NewSignOut accepted nothing")
	}
}
