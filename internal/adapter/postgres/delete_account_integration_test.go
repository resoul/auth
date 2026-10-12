//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"airlance.org/auth/internal/application/account"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/authflow"
	dpasskey "airlance.org/auth/internal/domain/passkey"
	"airlance.org/auth/internal/testutil"
)

func deletionFor(t *testing.T, e *changeEnv, c changer) (*account.DeleteAccount, string) {
	t.Helper()
	secret, hash, err := e.tickets.NewTicketSecret()
	if err != nil {
		t.Fatal(err)
	}
	pid, err := e.f.IDs.NewPasskeyID()
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := dpasskey.NewTicket(dpasskey.NewTicketParams{ID: pid, Kind: dpasskey.TicketStepUp, UserID: c.actor.UserID, SessionID: c.actor.SessionID, Operation: dpasskey.OperationDeleteAccount, SecretHash: hash, Now: e.clock.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.Do(t.Context(), func(ctx context.Context, s port.Stores) error { return s.Tickets.Create(ctx, ticket) }); err != nil {
		t.Fatal(err)
	}
	uc, err := account.NewDeleteAccount(account.DeleteAccountDeps{UnitOfWork: e.faults, Clock: e.clock, Tickets: e.tickets})
	if err != nil {
		t.Fatal(err)
	}
	return uc, secret
}

func TestDeleteAccountCascadesAndAnonymizesOnPostgres(t *testing.T) {
	e := newChangeEnv(t)
	c := e.account("delete@example.test")
	stranger := e.account("keep@example.test")
	e.begin(c, "pending@example.test")
	uc, secret := deletionFor(t, e, c)
	sess := e.f.Session(testutil.SessionSpec{User: c.user})
	refresh, _ := e.f.RefreshToken(testutil.RefreshSpec{Session: sess})
	login := e.f.Flow(testutil.FlowSpec{Email: c.user.Email().String(), KeyID: "otp-a"})
	credential := e.f.Credential(testutil.CredentialSpec{User: c.user})
	challenge := e.f.Challenge(testutil.ChallengeSpec{User: c.user})
	recovery := e.f.RecoveryCode(c.user, "recovery")
	if err := e.store.Do(t.Context(), func(ctx context.Context, s port.Stores) error {
		if err := s.Sessions.Create(ctx, sess); err != nil {
			return err
		}
		if err := s.Tokens.Create(ctx, refresh); err != nil {
			return err
		}
		if err := s.Credentials.Create(ctx, credential); err != nil {
			return err
		}
		if err := s.Challenges.Create(ctx, challenge); err != nil {
			return err
		}
		if err := s.Recovery.Replace(ctx, c.user.ID(), []*dpasskey.RecoveryCode{recovery}); err != nil {
			return err
		}
		if err := s.Flows.Create(ctx, login); err != nil {
			return err
		}
		if err := s.Outbox.Enqueue(ctx, port.MailJob{FlowID: login.ID(), Generation: login.Generation(), QuotaClass: authflow.QuotaUnknown, AvailableAt: e.clock.Now()}); err != nil {
			return err
		}
		return s.Audit.Record(ctx, port.AuditEvent{Type: port.AuditLoginSucceeded, Result: port.AuditSuccess, UserID: c.actor.UserID, SessionID: c.actor.SessionID, At: e.clock.Now()})
	}); err != nil {
		t.Fatal(err)
	}
	got, err := uc.Execute(t.Context(), account.DeleteAccountCommand{Actor: c.actor, StepUpSecret: secret})
	if err != nil || got.Outcome != account.OutcomeOK {
		t.Fatalf("delete = %+v, %v", got, err)
	}
	for table, want := range map[string]int{"users": 1, "sessions": 1, "recognized_clients": 1, "refresh_tokens": 0, "auth_flows": 0, "outbox": 0, "auth_tickets": 0, "passkey_credentials": 0, "passkey_challenges": 0, "recovery_codes": 0, "audit_events": 2} {
		if got := count(t, e.db, table); got != want {
			t.Errorf("%s = %d, want %d", table, got, want)
		}
	}
	var linked int
	if err := e.db.QueryRow("SELECT count(*) FROM audit_events WHERE user_id IS NOT NULL OR session_id IS NOT NULL").Scan(&linked); err != nil {
		t.Fatal(err)
	}
	if linked != 0 {
		t.Error("audit links survived")
	}
	if err := e.store.Do(t.Context(), func(ctx context.Context, s port.Stores) error {
		_, err := s.Users.Get(ctx, stranger.user.ID())
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentAccountDeletionCommitsOnceOnPostgres(t *testing.T) {
	e := newChangeEnv(t)
	c := e.account("delete@example.test")
	uc, secret := deletionFor(t, e, c)
	start := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	for range 8 {
		wg.Go(func() {
			<-start
			got, err := uc.Execute(t.Context(), account.DeleteAccountCommand{Actor: c.actor, StepUpSecret: secret})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				t.Errorf("delete: %v", err)
			}
			if got.Outcome == account.OutcomeOK {
				successes++
			}
		})
	}
	close(start)
	wg.Wait()
	if successes != 1 || count(t, e.db, "audit_events") != 1 {
		t.Errorf("successes = %d", successes)
	}
}

type failingDeletionAudit struct{ port.AuditLog }

func (f failingDeletionAudit) Record(context.Context, port.AuditEvent) error { return errBoom }

func TestAccountDeletionRollsBackOnPostgres(t *testing.T) {
	e := newChangeEnv(t)
	c := e.account("delete@example.test")
	uc, secret := deletionFor(t, e, c)
	e.faults.wrap = func(s port.Stores) port.Stores { s.Audit = failingDeletionAudit{s.Audit}; return s }
	_, err := uc.Execute(t.Context(), account.DeleteAccountCommand{Actor: c.actor, StepUpSecret: secret})
	if !errors.Is(err, errBoom) {
		t.Fatalf("error = %v", err)
	}
	if count(t, e.db, "users") != 1 || count(t, e.db, "sessions") != 1 {
		t.Error("rollback deleted account")
	}
	e.faults.wrap = nil
	got, err := uc.Execute(t.Context(), account.DeleteAccountCommand{Actor: c.actor, StepUpSecret: secret})
	if err != nil || got.Outcome != account.OutcomeOK {
		t.Fatalf("retry = %+v,%v", got, err)
	}
}
