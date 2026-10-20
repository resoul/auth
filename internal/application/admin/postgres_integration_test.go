//go:build integration

package admin_test

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"go.airlance.org/auth/internal/application/admin"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/operator"
	"go.airlance.org/auth/internal/domain/passkey"
	"go.airlance.org/auth/internal/testutil"
)

// newPostgresEnv runs the use cases of newEnv against PostgreSQL, where row locks decide what concurrent requests see.
func newPostgresEnv(t *testing.T) *env {
	t.Helper()

	e := newEnv(t)
	e.faults.inner = testutil.PostgresStore(t)

	return e
}

// listsAt makes listing an operator's keys wait at a meeting point after it read them, so that two transactions
// decide on what each saw before the other wrote.
type listsAt struct {
	port.OperatorRepository
	at *meet
}

func (l listsAt) ListCredentials(ctx context.Context, id operator.ID) ([]*passkey.Credential, error) {
	keys, err := l.OperatorRepository.ListCredentials(ctx, id)
	l.at.wait()

	return keys, err
}

// meet makes the first n callers wait for each other, for at most patience: if the code serializes them, the second
// never arrives while the first waits, and the first goes on alone.
type meet struct {
	mu       sync.Mutex
	n        int
	arrived  int
	ready    chan struct{}
	patience time.Duration
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

func TestTwoEnrollmentsCannotTakeTheLastKeyPlaceAtOnce(t *testing.T) {
	ctx := context.Background()
	e := newPostgresEnv(t)
	f := e.enrolled("ops@example.test")

	// The operator is one key short of the limit.
	for i := 1; i < operator.MaxCredentials-1; i++ {
		_, enrollment, err := e.operators.Enroll(ctx, "ops@example.test")
		must(t, err)
		begin, err := e.auth.BeginEnroll(ctx, admin.BeginEnrollCommand{Code: enrollment.Code, ClientIP: ip})
		must(t, err)
		res, err := e.auth.FinishEnroll(ctx, admin.FinishEnrollCommand{
			ChallengeID: begin.ChallengeID, Response: testutil.NewSoftAuthenticator(t, rpID, origin).Register(begin.Options), ClientIP: ip,
		})
		must(t, err)

		if res.Outcome != admin.OutcomeOK {
			t.Fatalf("key %d: %+v", i+1, res)
		}
	}

	// Two codes, each with its ceremony begun, from two addresses: the quota of one address would queue them anyway.
	type attempt struct {
		challenge string
		response  []byte
		from      netip.Addr
	}

	var attempts [2]attempt

	for i := range attempts {
		_, enrollment, err := e.operators.Enroll(ctx, "ops@example.test")
		must(t, err)
		begin, err := e.auth.BeginEnroll(ctx, admin.BeginEnrollCommand{Code: enrollment.Code, ClientIP: ip})
		must(t, err)

		if begin.Outcome != admin.OutcomeOK {
			t.Fatalf("begin %d = %+v", i, begin)
		}

		attempts[i] = attempt{
			challenge: begin.ChallengeID, response: testutil.NewSoftAuthenticator(t, rpID, origin).Register(begin.Options),
			from: netip.AddrFrom4([4]byte{198, 51, 100, byte(10 + i)}),
		}
	}

	at := &meet{n: 2, ready: make(chan struct{}), patience: time.Second}
	e.faults.wrap = func(s port.Stores) port.Stores {
		s.Operators = listsAt{OperatorRepository: s.Operators, at: at}
		return s
	}

	var (
		results [2]admin.FinishEnrollResult
		wg      sync.WaitGroup
	)

	for i := range attempts {
		wg.Add(1)

		go func() {
			defer wg.Done()

			got, err := e.auth.FinishEnroll(ctx, admin.FinishEnrollCommand{ChallengeID: attempts[i].challenge, Response: attempts[i].response, ClientIP: attempts[i].from})
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
		case r.Outcome == admin.OutcomeOK:
			ok++
		case r.Outcome == admin.OutcomeConflict && r.Reason == admin.ReasonTooManyKeys:
			refused++
		default:
			t.Errorf("unexpected result %+v", r)
		}
	}

	if ok != 1 || refused != 1 {
		t.Errorf("%d enrollments succeeded and %d were refused, want exactly one of each", ok, refused)
	}

	if err := e.faults.inner.Do(ctx, func(ctx context.Context, s port.Stores) error {
		keys, err := s.Operators.ListCredentials(ctx, f.op.ID())
		if err == nil && len(keys) != operator.MaxCredentials {
			t.Errorf("%d keys stored, want the limit of %d", len(keys), operator.MaxCredentials)
		}

		return err
	}); err != nil {
		t.Fatal(err)
	}
}
