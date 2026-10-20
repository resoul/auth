//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"go.airlance.org/auth/internal/adapter/postgres"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/testutil"
)

func TestALockHeldElsewhereEndsTheWaitAtTheLockTimeout(t *testing.T) {
	store := testutil.PostgresStore(t, postgres.WithTimeouts(postgres.Timeouts{Lock: 300 * time.Millisecond}))
	user := testutil.NewFactory(t, time.Now()).User(testutil.UserSpec{})

	if err := store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		_, _, err := st.Users.Ensure(ctx, user)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	// A transaction that holds the user and does not let go, such as one stuck behind a slow client.
	holding := make(chan struct{})
	release, open := gate(t)
	holder := inTx(store, func(ctx context.Context, st port.Stores) error {
		if _, err := st.Users.GetForUpdate(ctx, user.ID()); err != nil {
			return err
		}

		close(holding)
		<-release

		return nil
	})

	<-holding

	started := time.Now()
	err := store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		_, err := st.Users.GetForUpdate(ctx, user.ID())
		return err
	})
	waited := time.Since(started)

	open()

	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Errorf("the waiting transaction = %v, want lock_not_available (55P03)", err)
	}

	if waited > 2*time.Second {
		t.Errorf("the waiting transaction gave up after %v, want about the lock timeout", waited)
	}

	if err := within(t, "the holder", holder, 5*time.Second); err != nil {
		t.Errorf("the holder = %v", err)
	}
}

func TestATransactionEndsAtItsDeadline(t *testing.T) {
	store := testutil.PostgresStore(t, postgres.WithTimeouts(postgres.Timeouts{Transaction: 300 * time.Millisecond}))
	user := testutil.NewFactory(t, time.Now()).User(testutil.UserSpec{})

	err := store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		time.Sleep(500 * time.Millisecond) // a use case that stalls inside its transaction

		_, _, err := st.Users.Ensure(ctx, user)

		return err
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a transaction past its deadline = %v, want context.DeadlineExceeded", err)
	}

	// Nothing of it was kept, and the pool still serves the next transaction.
	if err := store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		if _, err := st.Users.Get(ctx, user.ID()); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("the user of the ended transaction = %v, want ErrNotFound", err)
		}

		return nil
	}); err != nil {
		t.Errorf("the next transaction = %v", err)
	}
}
