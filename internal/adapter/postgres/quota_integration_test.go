//go:build integration

package postgres_test

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"airlance.org/auth/internal/adapter/postgres"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/authflow"
	"airlance.org/auth/internal/domain/quota"
	"airlance.org/auth/internal/testutil"
)

func TestPostgresLimiterContract(t *testing.T) {
	testutil.RunLimiterContract(t, func(t *testing.T, p quota.Profile) port.UnitOfWork {
		store, _ := newStoreWith(t, postgres.WithQuota(p))
		return store
	})
}

// unknownVerify is a verification spend of an unknown client with its own binding and IP.
func unknownVerify(f *testutil.Factory, email string, i int, now time.Time) port.Spend {
	return port.Spend{
		Kind: quota.KindVerify, Email: f.User(testutil.UserSpec{Email: email}).Email(), Class: authflow.QuotaUnknown,
		Binding: testutil.BindingHash(fmt.Sprintf("binding-%d", i)),
		IP:      netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), Now: now,
	}
}

// The acceptance condition: the number of comparisons
// really admitted is the number the risk calculation assumes, whatever the concurrency,
// the IP and the bindings, and across the boundary of the window.
func TestDefaultProfileAdmitsExactlyTheBudgetedComparisons(t *testing.T) {
	store, _ := newStore(t)
	f := testutil.NewFactory(t, t0)
	const email = "target@example.test"

	admit := func(count int, now time.Time) int {
		t.Helper()
		var mu sync.Mutex
		var wg sync.WaitGroup
		admitted := 0
		for i := 0; i < count; i++ {
			s := unknownVerify(f, email, i, now)
			wg.Add(1)
			go func() {
				defer wg.Done()
				var ok bool
				err := store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
					var err error
					ok, err = st.Limiter.Allow(ctx, s)
					return err
				})
				if err != nil {
					t.Errorf("Allow: %v", err)
				}
				if ok {
					mu.Lock()
					admitted++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		return admitted
	}

	// The profile promises 50 a day per address; the pair budget (20) never blocks here
	// because every request brings a new binding.
	if got := admit(300, t0.Add(23*time.Hour+59*time.Minute)); got != 50 {
		t.Fatalf("admitted %d concurrent comparisons, want exactly 50", got)
	}
	if got := admit(100, t0.Add(24*time.Hour+30*time.Minute)); got != 0 {
		t.Errorf("admitted %d just after a calendar boundary, want 0: the window slides", got)
	}
	if got := admit(100, t0.Add(47*time.Hour+59*time.Minute+30*time.Second)); got != 50 {
		t.Errorf("admitted %d after the window passed, want 50", got)
	}
}

func TestDefaultProfileAdmitsExactlyTheBudgetedSends(t *testing.T) {
	store, _ := newStore(t)
	f := testutil.NewFactory(t, t0)
	email := f.User(testutil.UserSpec{Email: "target@example.test"}).Email()

	var mu sync.Mutex
	var wg sync.WaitGroup
	admitted := 0
	for i := 0; i < 100; i++ {
		s := port.Spend{
			Kind: quota.KindSend, Email: email, Class: authflow.QuotaUnknown,
			Binding: testutil.BindingHash(fmt.Sprintf("binding-%d", i)),
			IP:      netip.AddrFrom4([4]byte{10, 0, byte(i), 1}), Now: t0,
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			var ok bool
			err := store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
				var err error
				ok, err = st.Limiter.Allow(ctx, s)
				return err
			})
			if err != nil {
				t.Errorf("Allow: %v", err)
			}
			if ok {
				mu.Lock()
				admitted++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if admitted != 10 {
		t.Errorf("admitted %d sends to one address, want exactly 10", admitted)
	}
}

func TestQuotaRowsNameNoAddressAndDoNotOutliveTheWindow(t *testing.T) {
	store, db := newStore(t)
	f := testutil.NewFactory(t, t0)

	spend := unknownVerify(f, "target@example.test", 1, t0)
	err := store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		_, err := st.Limiter.Allow(ctx, spend)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}

	rows, err := db.Query(`SELECT column_name FROM information_schema.columns WHERE table_name = 'quota_events' AND table_schema = current_schema() ORDER BY column_name`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var cols []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatal(err)
		}
		cols = append(cols, c)
	}
	if len(cols) != 2 || cols[0] != "at" || cols[1] != "key_hash" {
		t.Errorf("quota_events columns = %v, want only at and key_hash", cols)
	}

	count := func() (n int) {
		t.Helper()
		if err := db.QueryRow(`SELECT count(*) FROM quota_events`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// Three budgets: the address, the pair and nothing for an IP on verify.
	if got := count(); got != 2 {
		t.Fatalf("rows after one spend = %d, want 2", got)
	}
	if res, err := store.Cleanup(context.Background(), t0.Add(23*time.Hour), postgres.DefaultCleanupPolicy()); err != nil || res.QuotaEvents != 0 || count() != 2 {
		t.Errorf("cleanup inside the window removed %d rows (%v), %d left", res.QuotaEvents, err, count())
	}
	if res, err := store.Cleanup(context.Background(), t0.Add(24*time.Hour), postgres.DefaultCleanupPolicy()); err != nil || res.QuotaEvents != 2 || count() != 0 {
		t.Errorf("cleanup after the window removed %d rows (%v), %d left, want 2 and 0", res.QuotaEvents, err, count())
	}
}

func TestASpendPrunesTheExpiredRowsOfItsOwnBudget(t *testing.T) {
	store, db := newStore(t)
	f := testutil.NewFactory(t, t0)
	spend := func(now time.Time) {
		t.Helper()
		s := unknownVerify(f, "target@example.test", 1, now)
		err := store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
			_, err := st.Limiter.Allow(ctx, s)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	spend(t0)
	spend(t0.Add(25 * time.Hour))
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM quota_events`).Scan(&n); err != nil || n != 2 {
		t.Errorf("rows = %d (%v), want the 2 of the new spend only", n, err)
	}
}
