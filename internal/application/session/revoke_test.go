package session_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"go.airlance.org/auth/internal/application/port"
	appsession "go.airlance.org/auth/internal/application/session"
	"go.airlance.org/auth/internal/domain/session"
	"go.airlance.org/auth/internal/testutil"
)

func TestRevokeSessionEndsSessionAndTokens(t *testing.T) {
	e := newEnv(t)
	issued, user := e.login("alice@example.test")
	child := e.exchange(issued.RefreshSecret)

	res, err := e.revoke.Execute(context.Background(), appsession.RevokeSessionCommand{ActorUserID: user.ID(), SessionID: issued.Session.ID().String()})
	if err != nil || res.Outcome != appsession.OutcomeOK {
		t.Fatalf("revoke = %+v, %v", res, err)
	}

	sess := e.session(issued.Session.ID())
	if !sess.RevokedAt().Equal(t0) || !e.allRevoked(sess.ID()) {
		t.Errorf("revokedAt=%v tokensRevoked=%v", sess.RevokedAt(), e.allRevoked(sess.ID()))
	}

	if res := e.exchange(child.NewRefreshSecret); res.Outcome != appsession.OutcomeDenied {
		t.Errorf("a signed-out session still refreshes: %+v", res)
	}
}

func TestRevokeKeepsOtherDevicesAlive(t *testing.T) {
	e := newEnv(t)
	laptop, user := e.login("alice@example.test")
	phone := e.loginAgain(user)

	if res, _ := e.revoke.Execute(context.Background(), appsession.RevokeSessionCommand{ActorUserID: user.ID(), SessionID: laptop.Session.ID().String()}); res.Outcome != appsession.OutcomeOK {
		t.Fatalf("revoke = %+v", res)
	}

	if !e.session(phone.Session.ID()).RevokedAt().IsZero() || e.allRevoked(phone.Session.ID()) {
		t.Error("revoking one device touched another")
	}

	if res := e.exchange(phone.RefreshSecret); res.Outcome != appsession.OutcomeOK {
		t.Errorf("phone refresh = %+v", res)
	}
}

func TestRevokeSessionHidesForeignAndMissingSessions(t *testing.T) {
	e := newEnv(t)
	issued, owner := e.login("alice@example.test")
	_, mallory := e.login("mallory@example.test")
	notStored := e.factory.Session(testutil.SessionSpec{User: owner}) // a valid ID that no store holds
	before := e.session(issued.Session.ID()).Record()

	cases := map[string]appsession.RevokeSessionCommand{
		"someone else's session": {ActorUserID: mallory.ID(), SessionID: issued.Session.ID().String()},
		"unknown session":        {ActorUserID: owner.ID(), SessionID: notStored.ID().String()},
		"malformed id":           {ActorUserID: owner.ID(), SessionID: "nope"},
		"no actor":               {SessionID: issued.Session.ID().String()},
	}
	for name, cmd := range cases {
		res, err := e.revoke.Execute(context.Background(), cmd)
		if err != nil || res.Outcome != appsession.OutcomeDenied {
			t.Errorf("%s: result = %+v, %v; want the same plain denial", name, res, err)
		}
	}

	if !reflect.DeepEqual(e.session(issued.Session.ID()).Record(), before) || e.allRevoked(issued.Session.ID()) {
		t.Error("a refused revoke changed the session")
	}
}

func TestRevokeSessionIsIdempotentAndKeepsTheFirstTime(t *testing.T) {
	e := newEnv(t)
	issued, user := e.login("alice@example.test")
	cmd := appsession.RevokeSessionCommand{ActorUserID: user.ID(), SessionID: issued.Session.ID().String()}

	if res, err := e.revoke.Execute(context.Background(), cmd); err != nil || res.Outcome != appsession.OutcomeOK {
		t.Fatalf("first revoke = %+v, %v", res, err)
	}

	e.clock.Advance(time.Hour)

	res, err := e.revoke.Execute(context.Background(), cmd)
	if err != nil || res.Outcome != appsession.OutcomeOK {
		t.Fatalf("second revoke = %+v, %v", res, err)
	}

	if got := e.session(issued.Session.ID()).RevokedAt(); !got.Equal(t0) {
		t.Errorf("RevokedAt = %v, want the first revocation %v", got, t0)
	}
}

func TestRevokeAllEndsEveryDeviceOfTheUserOnly(t *testing.T) {
	e := newEnv(t)
	laptop, user := e.login("alice@example.test")
	phone := e.loginAgain(user)
	stranger, _ := e.login("bob@example.test")

	res, err := e.revokeAll.Execute(context.Background(), appsession.RevokeAllCommand{ActorUserID: user.ID()})
	if err != nil || res.Outcome != appsession.OutcomeOK {
		t.Fatalf("revoke all = %+v, %v", res, err)
	}

	for name, id := range map[string]session.ID{"laptop": laptop.Session.ID(), "phone": phone.Session.ID()} {
		if e.session(id).RevokedAt().IsZero() || !e.allRevoked(id) {
			t.Errorf("%s survived revoke all", name)
		}
	}

	if !e.session(stranger.Session.ID()).RevokedAt().IsZero() || e.allRevoked(stranger.Session.ID()) {
		t.Error("another user's session was revoked")
	}

	if res := e.exchange(laptop.RefreshSecret); res.Outcome != appsession.OutcomeDenied {
		t.Errorf("laptop refresh after revoke all = %+v", res)
	}

	if res, _ := e.revokeAll.Execute(context.Background(), appsession.RevokeAllCommand{}); res.Outcome != appsession.OutcomeDenied {
		t.Errorf("revoke all without an actor = %+v", res)
	}
}

func TestRevokeUseCasesRequireDependencies(t *testing.T) {
	e := newEnv(t)
	for name, deps := range map[string]appsession.RevokeDeps{
		"unit of work": {Clock: e.clock}, "clock": {UnitOfWork: e.faults},
	} {
		if _, err := appsession.NewRevokeSession(deps); err == nil {
			t.Errorf("NewRevokeSession accepted a missing %s", name)
		}

		if _, err := appsession.NewRevokeAll(deps); err == nil {
			t.Errorf("NewRevokeAll accepted a missing %s", name)
		}
	}
}

func TestRevokeUseCasesLeaveAnAuditTrail(t *testing.T) {
	e := newEnv(t)
	laptop, user := e.login("alice@example.test")
	e.loginAgain(user)
	_, stranger := e.login("mallory@example.test")

	// A refused revoke leaves no trace of success.
	if res, _ := e.revoke.Execute(context.Background(), appsession.RevokeSessionCommand{ActorUserID: stranger.ID(), SessionID: laptop.Session.ID().String()}); res.Outcome != appsession.OutcomeDenied {
		t.Fatalf("setup: %+v", res)
	}

	if len(e.store.AuditEvents()) != 0 {
		t.Fatalf("a denied revoke recorded %d events", len(e.store.AuditEvents()))
	}

	if res, _ := e.revoke.Execute(context.Background(), appsession.RevokeSessionCommand{ActorUserID: user.ID(), SessionID: laptop.Session.ID().String()}); res.Outcome != appsession.OutcomeOK {
		t.Fatalf("revoke = %+v", res)
	}

	if res, _ := e.revokeAll.Execute(context.Background(), appsession.RevokeAllCommand{ActorUserID: user.ID()}); res.Outcome != appsession.OutcomeOK {
		t.Fatalf("revoke all = %+v", res)
	}

	events := e.store.AuditEvents()
	if len(events) != 2 {
		t.Fatalf("%d events, want 2", len(events))
	}

	if ev := events[0]; ev.Type != port.AuditSessionRevoked || ev.Result != port.AuditSuccess || ev.UserID != user.ID() || ev.SessionID != laptop.Session.ID() {
		t.Errorf("revoke event = %+v", ev)
	}

	if ev := events[1]; ev.Type != port.AuditAllSessionsRevoked || ev.UserID != user.ID() || !ev.SessionID.IsZero() {
		t.Errorf("revoke all event = %+v", ev)
	}
}
