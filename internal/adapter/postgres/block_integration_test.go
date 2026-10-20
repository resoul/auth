//go:build integration

package postgres_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/testutil"
)

// Issuing a session reads the user with GetForShare. A block that is under way holds the user's row, so a
// sign-in that reads at that moment waits for it and then sees the block; a plain read would still see the
// user as free and let the session through after the block revoked everything.
func TestASignInWaitsForABlockThatIsUnderWayAndSeesIt(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	f := testutil.NewFactory(t, time.Date(2027, 1, 1, 12, 0, 0, 0, time.UTC))
	user := f.User(testutil.UserSpec{})

	if err := store.Do(ctx, func(ctx context.Context, s port.Stores) error {
		_, _, err := s.Users.Ensure(ctx, user)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	blocking, release := make(chan struct{}), make(chan struct{})
	// A failed assertion must not leave the transaction open: store.Close would wait for it forever.
	var once sync.Once

	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)

	blockDone := make(chan error, 1)
	go func() {
		blockDone <- store.Do(ctx, func(ctx context.Context, s port.Stores) error {
			u, err := s.Users.Get(ctx, user.ID())
			if err != nil {
				return err
			}

			if err := u.Block(f.Clock.Now()); err != nil {
				return err
			}

			if err := s.Users.SetBlocked(ctx, u); err != nil {
				return err
			}

			close(blocking) // the row is held from here until the transaction ends
			<-release

			return nil
		})
	}()

	<-blocking

	// A plain read does not wait and still sees the old state: that is why issuing a session does not use it.
	if err := store.Do(ctx, func(ctx context.Context, s port.Stores) error {
		u, err := s.Users.Get(ctx, user.ID())
		if err != nil || u.Blocked() {
			t.Errorf("a plain read during the block = blocked %v, %v; want the committed, unblocked state", u != nil && u.Blocked(), err)
		}

		return nil
	}); err != nil {
		t.Fatal(err)
	}

	read := make(chan *identity.User, 1)

	go func() {
		_ = store.Do(ctx, func(ctx context.Context, s port.Stores) error {
			u, err := s.Users.GetForShare(ctx, user.ID())
			if err != nil {
				t.Errorf("GetForShare: %v", err)
			}

			read <- u

			return nil
		})
	}()

	select {
	case <-read:
		t.Fatal("GetForShare returned while a block was under way")
	case <-time.After(500 * time.Millisecond):
	}

	unblock()

	if err := <-blockDone; err != nil {
		t.Fatal(err)
	}

	select {
	case u := <-read:
		if u == nil || !u.Blocked() {
			t.Errorf("the sign-in read %+v after the block committed; want a blocked user", u)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the sign-in never got the user after the block committed")
	}
}

// The other way round: a sign-in that holds the user is not overtaken by a block, so the block's revocation
// finds the session the sign-in made.
func TestABlockWaitsForASignInThatHoldsTheUser(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	f := testutil.NewFactory(t, time.Date(2027, 1, 1, 12, 0, 0, 0, time.UTC))
	user := f.User(testutil.UserSpec{})

	if err := store.Do(ctx, func(ctx context.Context, s port.Stores) error {
		_, _, err := s.Users.Ensure(ctx, user)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	holding, release := make(chan struct{}), make(chan struct{})

	var once sync.Once

	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)

	signInDone := make(chan error, 1)
	go func() {
		signInDone <- store.Do(ctx, func(ctx context.Context, s port.Stores) error {
			if _, err := s.Users.GetForShare(ctx, user.ID()); err != nil {
				return err
			}

			close(holding)
			<-release

			return nil
		})
	}()

	<-holding

	blocked := make(chan error, 1)
	go func() {
		blocked <- store.Do(ctx, func(ctx context.Context, s port.Stores) error {
			u, err := s.Users.Get(ctx, user.ID())
			if err != nil {
				return err
			}

			if err := u.Block(f.Clock.Now()); err != nil {
				return err
			}

			return s.Users.SetBlocked(ctx, u)
		})
	}()

	select {
	case err := <-blocked:
		t.Fatalf("the block did not wait for the sign-in that holds the user: %v", err)
	case <-time.After(500 * time.Millisecond):
	}

	unblock()

	if err := <-signInDone; err != nil {
		t.Fatal(err)
	}

	if err := <-blocked; err != nil {
		t.Fatal(err)
	}
}
