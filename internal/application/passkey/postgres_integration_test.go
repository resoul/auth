//go:build integration

package passkey_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"go.airlance.org/auth/internal/application/passkey"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
	dpasskey "go.airlance.org/auth/internal/domain/passkey"
	"go.airlance.org/auth/internal/testutil"
)

// newPostgresEnv runs the use cases of newEnv against PostgreSQL. The in-memory store runs one transaction at a
// time and hides every race; row locks and READ COMMITTED are what these tests are about.
func newPostgresEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	e.faults.inner = testutil.PostgresStore(t)

	return e
}

// meet makes the first n callers wait for each other, for at most patience. It is how a test holds two
// transactions at the same statement: if the code serializes them, the second never arrives, the first gives up
// waiting, and the order is the one the locks impose.
type meet struct {
	mu       sync.Mutex
	n        int
	arrived  int
	ready    chan struct{}
	patience time.Duration
}

func newMeet(n int, patience time.Duration) *meet {
	return &meet{n: n, ready: make(chan struct{}), patience: patience}
}

func (m *meet) wait() {
	m.mu.Lock()

	m.arrived++
	if m.arrived == m.n {
		close(m.ready)
	}
	m.mu.Unlock()

	select {
	case <-m.ready:
	case <-time.After(m.patience):
	}
}

// listsAt wraps the credential repository so that listing the keys of a user waits at the meeting point after it
// has read them: the state a transaction decides on is then the state it saw before the other one wrote.
type listsAt struct {
	port.CredentialRepository
	at *meet
}

func (l listsAt) ListByUser(ctx context.Context, id identity.UserID) ([]*dpasskey.Credential, error) {
	list, err := l.CredentialRepository.ListByUser(ctx, id)
	l.at.wait()

	return list, err
}

func TestTwoFirstKeysCannotBeRegisteredAtOnce(t *testing.T) {
	e := newPostgresEnv(t)
	user := e.newUser()

	// Two valid email tickets of the same account, each with its own ceremony begun: the state before any key.
	type attempt struct {
		ticket    string
		binding   bindingSecret
		auth      *testutil.SoftAuthenticator
		challenge string
		options   []byte
	}

	var attempts [2]attempt
	for i := range attempts {
		a := &attempts[i]
		a.binding = e.newBinding()
		a.ticket = e.ticketFor(user, dpasskey.TicketEnroll, a.binding)
		a.auth = testutil.NewSoftAuthenticator(t, rpID, origin)
		begun, err := e.beginEnroll.Execute(context.Background(), passkey.BeginEnrollCommand{TicketSecret: a.ticket, BindingSecret: a.binding.secret})
		must(t, err)

		if begun.Outcome != passkey.OutcomeOK {
			t.Fatalf("begin %d = %+v", i, begun)
		}

		a.challenge = begun.ChallengeID
		a.options = a.auth.Register(begun.Options)
	}

	at := newMeet(2, time.Second)
	e.faults.wrap = func(s port.Stores) port.Stores {
		s.Credentials = listsAt{CredentialRepository: s.Credentials, at: at}
		return s
	}

	var (
		results [2]passkey.FinishEnrollResult
		wg      sync.WaitGroup
	)
	for i := range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()

			a := attempts[i]

			got, err := e.finishEnroll.Execute(context.Background(), passkey.FinishEnrollCommand{
				TicketSecret: a.ticket, BindingSecret: a.binding.secret, ChallengeID: a.challenge, Response: a.options,
				CredentialName: "Laptop", DeviceName: "test",
			})
			if err != nil {
				t.Errorf("finish %d: %v", i, err)
			}

			results[i] = got
		}()
	}

	wg.Wait()

	e.faults.wrap = nil

	ok, refused := 0, 0

	for _, r := range results {
		switch {
		case r.Outcome == passkey.OutcomeOK:
			ok++
		case r.Outcome == passkey.OutcomeDenied && r.Reason == passkey.ReasonAlreadyEnrolled:
			refused++
		default:
			t.Errorf("unexpected result %+v", r)
		}
	}

	if ok != 1 || refused != 1 {
		t.Errorf("%d registrations succeeded and %d were refused, want exactly one of each", ok, refused)
	}

	if n := len(e.credentials(user)); n != 1 {
		t.Errorf("%d keys stored, want 1", n)
	}

	if n := e.unusedCodes(user); n != dpasskey.RecoveryCodeCount {
		t.Errorf("%d recovery codes, want one set of %d", n, dpasskey.RecoveryCodeCount)
	}
}

func TestRecoveryReplacesEveryOldKeyOnPostgres(t *testing.T) {
	e := newPostgresEnv(t)
	holder := e.enroll()

	b := e.newBinding()
	second := e.ticketFor(holder.user, dpasskey.TicketSecondFactor, b)

	redeemed := e.redeem(second, b, holder.codes[0])
	if redeemed.Outcome != passkey.OutcomeOK {
		t.Fatalf("redeem = %+v", redeemed)
	}

	fresh := testutil.NewSoftAuthenticator(t, rpID, origin)
	if got := e.enrollWith(holder.user, fresh, redeemed.TicketSecret, b); got.Outcome != passkey.OutcomeOK {
		t.Fatalf("enroll after recovery = %+v", got)
	}

	if n := len(e.credentials(holder.user)); n != 1 {
		t.Errorf("%d keys after the recovery, want only the new one", n)
	}

	if r := e.signIn(holder.auth, "", e.newBinding()); r.Outcome == passkey.OutcomeOK {
		t.Error("the lost key signs in after the recovery")
	}

	if r := e.signIn(fresh, "", e.newBinding()); r.Outcome != passkey.OutcomeOK {
		t.Errorf("the new key does not sign in: %+v", r)
	}
}

func TestSignInAndRecoveryDoNotDeadlock(t *testing.T) {
	// A sign-in holds a credential and wants its user; a recovery holds the user and wants the credential. Both
	// take the user first, so they queue instead of waiting for each other until the database aborts one.
	for i := range 15 {
		e := newPostgresEnv(t)
		holder := e.enroll()
		b := e.newBinding()

		redeemed := e.redeem(e.ticketFor(holder.user, dpasskey.TicketSecondFactor, b), b, holder.codes[0])
		if redeemed.Outcome != passkey.OutcomeOK {
			t.Fatalf("round %d: redeem = %+v", i, redeemed)
		}

		fresh := testutil.NewSoftAuthenticator(t, rpID, origin)

		var wg sync.WaitGroup

		wg.Add(2)
		go func() { // the lost key keeps trying
			defer wg.Done()

			begun, err := e.beginLogin.Execute(context.Background(), passkey.BeginLoginCommand{})
			if err != nil {
				t.Errorf("round %d: begin login: %v", i, err)
				return
			}

			if _, err := e.finishLogin.Execute(context.Background(), passkey.FinishLoginCommand{
				ChallengeID: begun.ChallengeID, Response: holder.auth.Assert(begun.Options), BindingSecret: e.newBinding().secret, DeviceName: "x", ClientIP: clientAddr,
			}); err != nil {
				t.Errorf("round %d: finish login: %v", i, err)
			}
		}()
		go func() {
			defer wg.Done()

			begun, err := e.beginEnroll.Execute(context.Background(), passkey.BeginEnrollCommand{TicketSecret: redeemed.TicketSecret, BindingSecret: b.secret})
			if err != nil || begun.Outcome != passkey.OutcomeOK {
				t.Errorf("round %d: begin enroll = %+v, %v", i, begun, err)
				return
			}

			got, err := e.finishEnroll.Execute(context.Background(), passkey.FinishEnrollCommand{
				TicketSecret: redeemed.TicketSecret, BindingSecret: b.secret, ChallengeID: begun.ChallengeID, Response: fresh.Register(begun.Options),
				CredentialName: "New", DeviceName: "test",
			})
			if err != nil || got.Outcome != passkey.OutcomeOK {
				t.Errorf("round %d: finish enroll = %+v, %v", i, got, err)
			}
		}()

		wg.Wait()
	}
}
