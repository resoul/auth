package account_test

import (
	"context"
	"errors"
	"testing"

	"airlance.org/auth/internal/application/account"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/authflow"
	"airlance.org/auth/internal/domain/identity"
	dpasskey "airlance.org/auth/internal/domain/passkey"
	"airlance.org/auth/internal/testutil"
)

func (e *env) deletion() *account.DeleteAccount {
	e.t.Helper()
	u, err := account.NewDeleteAccount(account.DeleteAccountDeps{UnitOfWork: e.faults, Clock: e.clock, Tickets: e.tickets})
	must(e.t, err)
	return u
}

func TestDeleteAccountRemovesAccessAndMailAndClearsAuditReferences(t *testing.T) {
	e := newEnv(t)
	s := e.signedIn("delete@example.test")
	e.otherSession(s, "other")
	stranger := e.signedIn("keep@example.test")
	login := e.factory.Flow(testutil.FlowSpec{Email: s.user.Email().String(), KeyID: "otp-a"})
	e.do(func(ctx context.Context, st port.Stores) error {
		if err := st.Flows.Create(ctx, login); err != nil {
			return err
		}
		if err := st.Outbox.Enqueue(ctx, port.MailJob{FlowID: login.ID(), Generation: login.Generation(), QuotaClass: authflow.QuotaUnknown, AvailableAt: e.clock.Now()}); err != nil {
			return err
		}
		return st.Audit.Record(ctx, port.AuditEvent{Type: port.AuditLoginSucceeded, Result: port.AuditSuccess, UserID: s.actor.UserID, SessionID: s.actor.SessionID, At: e.clock.Now()})
	})
	e.begin(s, "pending@example.test")
	secret := e.stepUp(s.actor, dpasskey.OperationDeleteAccount)
	got, err := e.deletion().Execute(context.Background(), account.DeleteAccountCommand{Actor: s.actor, StepUpSecret: secret})
	must(t, err)
	if got.Outcome != account.OutcomeOK {
		t.Fatalf("delete = %+v", got)
	}
	if _, ok := e.userByEmail(s.user.Email().String()); ok {
		t.Error("user survived")
	}
	if e.store.SessionCount() != 1 || e.store.TicketCount() != 0 || e.store.FlowCount() != 0 || len(e.store.OutboxJobs()) != 0 {
		t.Error("account data or queued mail survived")
	}
	if _, ok := e.store.Session(stranger.actor.SessionID); !ok {
		t.Error("another user's session was deleted")
	}
	events := e.store.AuditEvents()
	if len(events) != 2 || events[1].Type != port.AuditAccountDeleted {
		t.Fatalf("audit = %+v", events)
	}
	for _, event := range events {
		if !event.UserID.IsZero() || !event.SessionID.IsZero() {
			t.Error("audit references survived")
		}
	}
	got, err = e.deletion().Execute(context.Background(), account.DeleteAccountCommand{Actor: s.actor, StepUpSecret: secret})
	must(t, err)
	if got.Outcome != account.OutcomeDenied {
		t.Errorf("replay = %+v", got)
	}
}

func TestDeleteAccountRequiresItsFreshProofAndActiveSession(t *testing.T) {
	for _, kind := range []string{"missing", "malformed", "operation", "user", "session", "expired", "revoked"} {
		t.Run(kind, func(t *testing.T) {
			e := newEnv(t)
			s := e.signedIn("delete@example.test")
			secret := e.stepUp(s.actor, dpasskey.OperationDeleteAccount)
			switch kind {
			case "missing":
				secret = ""
			case "malformed":
				secret = "!"
			case "operation":
				secret = e.stepUp(s.actor, dpasskey.OperationChangeEmail)
			case "user":
				secret = e.stepUp(e.signedIn("stranger@example.test").actor, dpasskey.OperationDeleteAccount)
			case "session":
				secret = e.stepUp(e.otherSession(s, "other"), dpasskey.OperationDeleteAccount)
			case "expired":
				e.clock.Advance(dpasskey.StepUpTicketTTL)
			case "revoked":
				e.revoke(s.actor)
			}
			got, err := e.deletion().Execute(context.Background(), account.DeleteAccountCommand{Actor: s.actor, StepUpSecret: secret})
			must(t, err)
			want := account.OutcomeStepUpRequired
			if kind == "revoked" {
				want = account.OutcomeDenied
			}
			if got.Outcome != want {
				t.Errorf("got %+v, want %s", got, want)
			}
			if _, ok := e.userByEmail(s.user.Email().String()); !ok {
				t.Error("user deleted without proof")
			}
		})
	}
}

type failingDeleteAudit struct{ port.AuditLog }

func (f failingDeleteAudit) Record(context.Context, port.AuditEvent) error { return errBoom }

func TestDeleteAccountRollsBackProofWhenAuditFails(t *testing.T) {
	e := newEnv(t)
	s := e.signedIn("delete@example.test")
	secret := e.stepUp(s.actor, dpasskey.OperationDeleteAccount)
	e.faults.wrap = func(st port.Stores) port.Stores { st.Audit = failingDeleteAudit{st.Audit}; return st }
	_, err := e.deletion().Execute(context.Background(), account.DeleteAccountCommand{Actor: s.actor, StepUpSecret: secret})
	if !errors.Is(err, errBoom) {
		t.Fatalf("error = %v", err)
	}
	if _, ok := e.userByEmail(s.user.Email().String()); !ok {
		t.Error("user deleted on rollback")
	}
	e.faults.wrap = nil
	got, err := e.deletion().Execute(context.Background(), account.DeleteAccountCommand{Actor: s.actor, StepUpSecret: secret})
	must(t, err)
	if got.Outcome != account.OutcomeOK {
		t.Fatalf("retry = %+v", got)
	}
}

func TestNewDeleteAccountRequiresDependencies(t *testing.T) {
	if _, err := account.NewDeleteAccount(account.DeleteAccountDeps{}); err == nil {
		t.Error("accepted missing dependencies")
	}
}

// failingAfterDelete proves that the cascades and audit also roll back after deletion ran.
type failingAfterDelete struct{ port.UserRepository }

func (f failingAfterDelete) Delete(ctx context.Context, id identity.UserID) error {
	if err := f.UserRepository.Delete(ctx, id); err != nil {
		return err
	}
	return errBoom
}

func TestDeleteAccountRollsBackCascadesAuditAndProof(t *testing.T) {
	e := newEnv(t)
	s := e.signedIn("delete@example.test")
	e.begin(s, "pending@example.test")
	secret := e.stepUp(s.actor, dpasskey.OperationDeleteAccount)
	before := len(e.store.OutboxJobs())
	e.faults.wrap = func(st port.Stores) port.Stores { st.Users = failingAfterDelete{st.Users}; return st }
	_, err := e.deletion().Execute(t.Context(), account.DeleteAccountCommand{Actor: s.actor, StepUpSecret: secret})
	if !errors.Is(err, errBoom) {
		t.Fatalf("error = %v", err)
	}
	if e.store.UserCount() != 1 || e.store.SessionCount() != 1 || len(e.store.OutboxJobs()) != before || len(e.store.AuditEvents()) != 0 {
		t.Error("rollback lost data or kept deletion audit")
	}
	e.faults.wrap = nil
	got, err := e.deletion().Execute(t.Context(), account.DeleteAccountCommand{Actor: s.actor, StepUpSecret: secret})
	must(t, err)
	if got.Outcome != account.OutcomeOK {
		t.Fatalf("retry = %+v", got)
	}
}
