package session_test

import (
	"context"
	"testing"

	"airlance.org/auth/internal/application/port"
	appsession "airlance.org/auth/internal/application/session"
	"airlance.org/auth/internal/testutil"
)

const laptopBinding = testutil.DefaultBindingSecret // e.login's device
const phoneBinding = "other-device"                 // e.loginAgain's device

func (e *env) signOutUseCase() *appsession.SignOut {
	e.t.Helper()
	u, err := appsession.NewSignOut(appsession.RevokeDeps{UnitOfWork: e.faults, Clock: e.clock})
	if err != nil {
		e.t.Fatal(err)
	}
	return u
}

func (e *env) signOut(actor appsession.Actor, scope appsession.SignOutScope, forget bool) appsession.RevokeResult {
	e.t.Helper()
	res, err := e.signOutUseCase().Execute(context.Background(), appsession.SignOutCommand{Actor: actor, Scope: scope, ForgetClient: forget})
	if err != nil {
		e.t.Fatalf("sign out: %v", err)
	}
	return res
}

func (e *env) lastAudit() port.AuditEvent {
	e.t.Helper()
	events := e.store.AuditEvents()
	if len(events) == 0 {
		e.t.Fatal("no audit events")
	}
	return events[len(events)-1]
}

func TestSignOutOfTheCurrentSessionKeepsTheDeviceRecognized(t *testing.T) {
	e := newEnv(t)
	laptop, user := e.login("alice@example.test")
	phone := e.loginAgain(user)
	e.recognize(user, laptopBinding)
	e.recognize(user, phoneBinding)

	if res := e.signOut(e.actor(laptop), appsession.ScopeCurrent, false); res.Outcome != appsession.OutcomeOK {
		t.Fatalf("sign out = %+v", res)
	}
	sess := e.session(laptop.Session.ID())
	if !sess.RevokedAt().Equal(t0) || !e.allRevoked(sess.ID()) {
		t.Errorf("the session survived: revoked %v, tokens revoked %v", sess.RevokedAt(), e.allRevoked(sess.ID()))
	}
	if res := e.exchange(laptop.RefreshSecret); res.Outcome != appsession.OutcomeDenied {
		t.Errorf("the signed-out device still refreshes: %+v", res)
	}
	if !e.session(phone.Session.ID()).RevokedAt().IsZero() || e.exchange(phone.RefreshSecret).Outcome != appsession.OutcomeOK {
		t.Error("signing out one device touched another")
	}
	for _, b := range []string{laptopBinding, phoneBinding} {
		if _, ok := e.recognizedUntil(user, b); !ok {
			t.Errorf("an ordinary sign-out forgot the device of binding %s", b)
		}
	}
	if ev := e.lastAudit(); ev.Type != port.AuditSessionRevoked || ev.Fields["scope"] != "current" || ev.Fields["forget_client"] != "false" || ev.UserID != user.ID() {
		t.Errorf("audit event = %+v", ev)
	}
}

func TestSignOutWithForgetClientEndsOnlyThisDevicesRecognition(t *testing.T) {
	e := newEnv(t)
	laptop, user := e.login("alice@example.test")
	e.loginAgain(user)
	e.recognize(user, laptopBinding)
	e.recognize(user, phoneBinding)

	if res := e.signOut(e.actor(laptop), appsession.ScopeCurrent, true); res.Outcome != appsession.OutcomeOK {
		t.Fatalf("sign out = %+v", res)
	}
	if _, ok := e.recognizedUntil(user, laptopBinding); ok {
		t.Error("forget_client left the device recognized")
	}
	if _, ok := e.recognizedUntil(user, phoneBinding); !ok {
		t.Error("forget_client forgot another device")
	}
	if ev := e.lastAudit(); ev.Fields["forget_client"] != "true" {
		t.Errorf("audit event = %+v", ev)
	}
}

func TestSignOutEverywhereEndsEverySessionAndRecognitionOfTheUserOnly(t *testing.T) {
	e := newEnv(t)
	laptop, user := e.login("alice@example.test")
	phone := e.loginAgain(user)
	bobSession, bob := e.login("bob@example.test")
	e.recognize(user, laptopBinding)
	e.recognize(user, phoneBinding)
	e.recognize(bob, laptopBinding)

	if res := e.signOut(e.actor(laptop), appsession.ScopeAll, false); res.Outcome != appsession.OutcomeOK {
		t.Fatalf("sign out = %+v", res)
	}
	for name, issued := range map[string]appsession.Issued{"laptop": laptop, "phone": phone} {
		if e.session(issued.Session.ID()).RevokedAt().IsZero() || !e.allRevoked(issued.Session.ID()) {
			t.Errorf("the %s session survived", name)
		}
		if res := e.exchange(issued.RefreshSecret); res.Outcome != appsession.OutcomeDenied {
			t.Errorf("the %s still refreshes", name)
		}
	}
	for _, b := range []string{laptopBinding, phoneBinding} {
		if _, ok := e.recognizedUntil(user, b); ok {
			t.Errorf("signing out everywhere left binding %s recognized", b)
		}
	}
	// Another user is not affected, in sessions, tokens or recognition.
	if !e.session(bobSession.Session.ID()).RevokedAt().IsZero() || e.allRevoked(bobSession.Session.ID()) {
		t.Error("Bob's session was revoked")
	}
	if _, ok := e.recognizedUntil(bob, laptopBinding); !ok {
		t.Error("Bob's device was forgotten")
	}
	if ev := e.lastAudit(); ev.Type != port.AuditAllSessionsRevoked || ev.Fields["scope"] != "all" || ev.UserID != user.ID() {
		t.Errorf("audit event = %+v", ev)
	}
}

func TestRevokeAllAlsoForgetsEveryDevice(t *testing.T) {
	e := newEnv(t)
	_, user := e.login("alice@example.test")
	e.recognize(user, laptopBinding)
	revokeAll, err := appsession.NewRevokeAll(appsession.RevokeDeps{UnitOfWork: e.faults, Clock: e.clock})
	if err != nil {
		t.Fatal(err)
	}
	if res, err := revokeAll.Execute(context.Background(), appsession.RevokeAllCommand{ActorUserID: user.ID()}); err != nil || res.Outcome != appsession.OutcomeOK {
		t.Fatal(res, err)
	}
	if _, ok := e.recognizedUntil(user, laptopBinding); ok {
		t.Error("RevokeAll left the device recognized")
	}
}

func TestSignOutRefusesAForeignOrUnknownSessionAndChangesNothing(t *testing.T) {
	e := newEnv(t)
	issued, user := e.login("alice@example.test")
	_, mallory := e.login("mallory@example.test")
	e.recognize(user, laptopBinding)
	ghost := e.factory.Session(testutil.SessionSpec{User: user})

	for name, cmd := range map[string]appsession.SignOutCommand{
		"someone else's session": {Actor: appsession.Actor{UserID: mallory.ID(), SessionID: issued.Session.ID()}, Scope: appsession.ScopeAll},
		"a session that is gone": {Actor: appsession.Actor{UserID: user.ID(), SessionID: ghost.ID()}, Scope: appsession.ScopeCurrent},
		"no actor":               {Scope: appsession.ScopeCurrent},
		"an unknown scope":       {Actor: e.actor(issued), Scope: "everything"},
		"no scope":               {Actor: e.actor(issued)},
	} {
		res, err := e.signOutUseCase().Execute(context.Background(), cmd)
		if err != nil || res.Outcome != appsession.OutcomeDenied {
			t.Errorf("%s: result = %+v, %v", name, res, err)
		}
	}
	if !e.session(issued.Session.ID()).RevokedAt().IsZero() || e.allRevoked(issued.Session.ID()) {
		t.Error("a refused sign-out revoked a session")
	}
	if _, ok := e.recognizedUntil(user, laptopBinding); !ok {
		t.Error("a refused sign-out forgot a device")
	}
	if len(e.store.AuditEvents()) != 0 {
		t.Errorf("a refused sign-out left audit events: %+v", e.store.AuditEvents())
	}
}

func TestSignOutIsRepeatable(t *testing.T) {
	e := newEnv(t)
	issued, _ := e.login("alice@example.test")
	for i := 0; i < 2; i++ {
		if res := e.signOut(e.actor(issued), appsession.ScopeCurrent, false); res.Outcome != appsession.OutcomeOK {
			t.Fatalf("sign out %d = %+v", i+1, res)
		}
	}
	e.clock.Advance(day)
	if res := e.signOut(e.actor(issued), appsession.ScopeCurrent, false); res.Outcome != appsession.OutcomeOK {
		t.Fatalf("a late repeat = %+v", res)
	}
	if got := e.session(issued.Session.ID()).RevokedAt(); !got.Equal(t0) {
		t.Errorf("revoked at %v, want the first time %v", got, t0)
	}
}

func TestATechnicalFailureRollsTheSignOutBack(t *testing.T) {
	e := newEnv(t)
	laptop, user := e.login("alice@example.test")
	e.recognize(user, laptopBinding)
	e.faults.wrap = func(s port.Stores) port.Stores { s.Audit = failingAudit{}; return s }

	_, err := e.signOutUseCase().Execute(context.Background(), appsession.SignOutCommand{Actor: e.actor(laptop), Scope: appsession.ScopeCurrent, ForgetClient: true})
	if err == nil {
		t.Fatal("the injected failure did not surface")
	}
	e.faults.wrap = nil
	if !e.session(laptop.Session.ID()).RevokedAt().IsZero() || e.allRevoked(laptop.Session.ID()) {
		t.Error("the session was revoked although the sign-out failed")
	}
	if _, ok := e.recognizedUntil(user, laptopBinding); !ok {
		t.Error("the device was forgotten although the sign-out failed")
	}
}
