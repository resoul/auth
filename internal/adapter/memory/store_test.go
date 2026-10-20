package memory_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go.airlance.org/auth/internal/adapter/memory"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/authflow"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/testutil"
)

var (
	now     = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	errBoom = errors.New("boom")
	ctx     = context.Background()
)

func TestCommitPersistsEveryStore(t *testing.T) {
	f := testutil.NewFactory(t, now)
	flow := f.Flow(testutil.FlowSpec{})
	user := f.User(testutil.UserSpec{})
	store := memory.NewStore()

	err := store.Do(ctx, func(ctx context.Context, s port.Stores) error {
		if err := s.Flows.Create(ctx, flow); err != nil {
			return err
		}

		if _, created, err := s.Users.Ensure(ctx, user); err != nil || !created {
			return errors.Join(err, errors.New("user not created"))
		}

		if err := s.Outbox.Enqueue(ctx, port.MailJob{FlowID: flow.ID(), Generation: 1}); err != nil {
			return err
		}

		_, err := s.Limiter.Allow(ctx, port.Spend{Kind: port.SpendSend, Email: flow.Email(), Class: authflow.QuotaUnknown, Now: now})

		return err
	})
	if err != nil {
		t.Fatalf("Do: %v", err)
	}

	if _, ok := store.Flow(flow.ID()); !ok {
		t.Error("flow lost")
	}

	if _, ok := store.User(user.Email()); !ok {
		t.Error("user lost")
	}

	if len(store.OutboxJobs()) != 1 || store.Spent(port.SpendSend, flow.Email()) != 1 {
		t.Errorf("jobs=%d spent=%d", len(store.OutboxJobs()), store.Spent(port.SpendSend, flow.Email()))
	}
}

func TestErrorRollsBackEveryStore(t *testing.T) {
	f := testutil.NewFactory(t, now)
	flow := f.Flow(testutil.FlowSpec{})
	user := f.User(testutil.UserSpec{})
	store := memory.NewStore()

	err := store.Do(ctx, func(ctx context.Context, s port.Stores) error {
		_ = s.Flows.Create(ctx, flow)
		_, _, _ = s.Users.Ensure(ctx, user)
		_ = s.Outbox.Enqueue(ctx, port.MailJob{FlowID: flow.ID(), Generation: 1})
		_, _ = s.Limiter.Allow(ctx, port.Spend{Kind: port.SpendSend, Email: flow.Email(), Class: authflow.QuotaUnknown, Now: now})

		return errBoom
	})
	if !errors.Is(err, errBoom) {
		t.Fatalf("Do error = %v, want boom", err)
	}

	if store.FlowCount() != 0 || store.UserCount() != 0 || len(store.OutboxJobs()) != 0 || store.Spent(port.SpendSend, flow.Email()) != 0 {
		t.Error("a failed transaction left data behind")
	}
}

func TestChangesToLoadedFlowAreInvisibleUntilSaved(t *testing.T) {
	f := testutil.NewFactory(t, now)
	flow := f.Flow(testutil.FlowSpec{})

	store := memory.NewStore()
	if err := store.Do(ctx, func(ctx context.Context, s port.Stores) error { return s.Flows.Create(ctx, flow) }); err != nil {
		t.Fatal(err)
	}

	binding := testutil.BindingHash(testutil.DefaultBindingSecret)

	// Mutating a loaded flow without Save changes nothing.
	_ = store.Do(ctx, func(ctx context.Context, s port.Stores) error {
		loaded, err := s.Flows.GetForUpdate(ctx, flow.ID())
		if err != nil {
			return err
		}

		_, err = loaded.Reserve(now, authflow.PurposeLogin, binding, authflow.DefaultPolicy())

		return err
	})
	if got, _ := store.Flow(flow.ID()); got.Attempts() != 0 {
		t.Errorf("attempts = %d without Save", got.Attempts())
	}

	// Save inside a transaction that then fails is rolled back; a committed Save sticks.
	save := func(fail bool) {
		_ = store.Do(ctx, func(ctx context.Context, s port.Stores) error {
			loaded, _ := s.Flows.GetForUpdate(ctx, flow.ID())
			if _, err := loaded.Reserve(now, authflow.PurposeLogin, binding, authflow.DefaultPolicy()); err != nil {
				return err
			}

			if err := s.Flows.Save(ctx, loaded); err != nil {
				return err
			}

			if fail {
				return errBoom
			}

			return nil
		})
	}
	save(true)

	if got, _ := store.Flow(flow.ID()); got.Attempts() != 0 {
		t.Errorf("attempts = %d after a rolled back Save", got.Attempts())
	}

	save(false)

	if got, _ := store.Flow(flow.ID()); got.Attempts() != 1 {
		t.Errorf("attempts = %d after a committed Save", got.Attempts())
	}
}

func TestFlowRepositoryErrors(t *testing.T) {
	f := testutil.NewFactory(t, now)
	flow := f.Flow(testutil.FlowSpec{})
	store := memory.NewStore()

	_ = store.Do(ctx, func(ctx context.Context, s port.Stores) error {
		if _, err := s.Flows.GetForUpdate(ctx, flow.ID()); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("GetForUpdate on a missing flow = %v, want ErrNotFound", err)
		}

		if err := s.Flows.Save(ctx, flow); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("Save of a missing flow = %v, want ErrNotFound", err)
		}

		if err := s.Flows.Create(ctx, flow); err != nil {
			t.Errorf("Create: %v", err)
		}

		if err := s.Flows.Create(ctx, flow); err == nil {
			t.Error("Create accepted a duplicate id")
		}

		return nil
	})
}

func TestEnsureUserIsIdempotentPerEmail(t *testing.T) {
	f := testutil.NewFactory(t, now)
	first := f.User(testutil.UserSpec{Email: "alice@example.test"})
	second := f.User(testutil.UserSpec{Email: "Alice@Example.test"})
	store := memory.NewStore()

	_ = store.Do(ctx, func(ctx context.Context, s port.Stores) error {
		u1, created1, err1 := s.Users.Ensure(ctx, first)

		u2, created2, err2 := s.Users.Ensure(ctx, second)
		if err1 != nil || err2 != nil || !created1 || created2 {
			t.Errorf("created = %v/%v, errors = %v/%v", created1, created2, err1, err2)
		}

		if u1.ID() != first.ID() || u2.ID() != first.ID() {
			t.Errorf("second Ensure returned %s, want the first user %s", u2.ID(), first.ID())
		}

		return nil
	})
	if store.UserCount() != 1 {
		t.Errorf("users = %d", store.UserCount())
	}
}

func allow(t *testing.T, store *memory.Store, kind port.SpendKind, email identity.Email) bool {
	t.Helper()

	var allowed bool

	err := store.Do(ctx, func(ctx context.Context, s port.Stores) error {
		var err error

		allowed, err = s.Limiter.Allow(ctx, port.Spend{Kind: kind, Email: email, Class: authflow.QuotaUnknown, Now: now})

		return err
	})
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}

	return allowed
}

func TestLimiterCapsEachKindPerEmail(t *testing.T) {
	f := testutil.NewFactory(t, now)
	alice := f.User(testutil.UserSpec{}).Email()
	bob := f.User(testutil.UserSpec{}).Email()
	store := memory.NewStore(memory.WithLimits(2, memory.Unlimited))

	for i := 1; i <= 2; i++ {
		if !allow(t, store, port.SpendSend, alice) {
			t.Fatalf("send %d denied", i)
		}
	}

	if allow(t, store, port.SpendSend, alice) {
		t.Error("third send allowed")
	}

	if got := store.Spent(port.SpendSend, alice); got != 2 {
		t.Errorf("a denial changed the counter: %d", got)
	}

	if !allow(t, store, port.SpendSend, bob) {
		t.Error("another email shares the quota")
	}

	for i := 0; i < 50; i++ {
		if !allow(t, store, port.SpendVerify, alice) {
			t.Fatal("unlimited verify quota denied")
		}
	}
}

func TestLimiterRejectsUnknownKind(t *testing.T) {
	store := memory.NewStore()

	err := store.Do(ctx, func(ctx context.Context, s port.Stores) error {
		_, err := s.Limiter.Allow(ctx, port.Spend{Kind: "other", Class: authflow.QuotaUnknown, Now: now})
		return err
	})
	if err == nil {
		t.Error("unknown spend kind accepted")
	}
}

func TestTransactionsDoNotOverspendUnderConcurrency(t *testing.T) {
	email := testutil.NewFactory(t, now).User(testutil.UserSpec{}).Email()
	store := memory.NewStore(memory.WithLimits(10, memory.Unlimited))

	var (
		wg sync.WaitGroup
		mu sync.Mutex
	)

	allowed := 0

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			if allow(t, store, port.SpendSend, email) {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	if allowed != 10 {
		t.Errorf("allowed = %d, want exactly the limit 10", allowed)
	}
}

func TestDoSkipsCallbackWhenContextIsCancelled(t *testing.T) {
	store := memory.NewStore()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()

	called := false

	err := store.Do(cancelled, func(context.Context, port.Stores) error { called = true; return nil })
	if !errors.Is(err, context.Canceled) || called {
		t.Errorf("error = %v, called = %v", err, called)
	}
}
