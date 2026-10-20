package testutil

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
)

func invitationFor(t *testing.T, raw string, now time.Time, ttl time.Duration) *identity.Invitation {
	t.Helper()

	email, err := identity.ParseEmail(raw)
	if err != nil {
		t.Fatal(err)
	}

	inv, err := identity.NewInvitation(email, now, ttl)
	if err != nil {
		t.Fatal(err)
	}

	return inv
}

func invitationContract(t *testing.T, newUoW NewUnitOfWork) {
	week := 7 * 24 * time.Hour

	t.Run("a saved invitation is found while it is active", func(t *testing.T) {
		uow := newUoW(t)
		inv := invitationFor(t, "guest@example.test", contractNow, week)
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error { return s.Invitations.Save(ctx, inv) })
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			got, err := s.Invitations.FindActive(ctx, inv.Email(), contractNow.Add(week-time.Second))
			if err != nil || got.Record() != inv.Record() {
				t.Errorf("FindActive = %+v, %v; want %+v", got, err, inv.Record())
			}

			if _, err := s.Invitations.FindActive(ctx, inv.Email(), contractNow.Add(week)); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("FindActive at the expiry instant = %v, want ErrNotFound", err)
			}

			other, _ := identity.ParseEmail("other@example.test")
			if _, err := s.Invitations.FindActive(ctx, other, contractNow); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("FindActive of another address = %v, want ErrNotFound", err)
			}

			return nil
		})
	})

	t.Run("saving again renews the invitation instead of adding another", func(t *testing.T) {
		uow := newUoW(t)
		first := invitationFor(t, "guest@example.test", contractNow, 24*time.Hour)
		again := invitationFor(t, "guest@example.test", contractNow.Add(time.Hour), week)
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if err := s.Invitations.Save(ctx, first); err != nil {
				return err
			}

			return s.Invitations.Save(ctx, again)
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			list, err := s.Invitations.List(ctx)
			if err != nil || len(list) != 1 || list[0].Record() != again.Record() {
				t.Errorf("List = %v, %v; want only the renewed invitation", list, err)
			}

			return nil
		})
	})

	t.Run("consume uses an active invitation once", func(t *testing.T) {
		uow := newUoW(t)
		inv := invitationFor(t, "guest@example.test", contractNow, week)
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error { return s.Invitations.Save(ctx, inv) })
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if ok, err := s.Invitations.Consume(ctx, inv.Email(), contractNow.Add(time.Hour)); err != nil || !ok {
				t.Errorf("first Consume = %v, %v", ok, err)
			}

			if ok, err := s.Invitations.Consume(ctx, inv.Email(), contractNow.Add(time.Hour)); err != nil || ok {
				t.Errorf("second Consume = %v, %v; want false", ok, err)
			}

			if _, err := s.Invitations.FindActive(ctx, inv.Email(), contractNow); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("the consumed invitation is still found: %v", err)
			}

			return nil
		})
	})

	t.Run("an expired invitation is not consumed and stays listed until swept", func(t *testing.T) {
		uow := newUoW(t)
		inv := invitationFor(t, "guest@example.test", contractNow, 24*time.Hour)
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error { return s.Invitations.Save(ctx, inv) })
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if ok, err := s.Invitations.Consume(ctx, inv.Email(), contractNow.Add(24*time.Hour)); err != nil || ok {
				t.Errorf("Consume of an expired invitation = %v, %v; want false", ok, err)
			}

			if list, _ := s.Invitations.List(ctx); len(list) != 1 {
				t.Errorf("the expired invitation left the list: %d", len(list))
			}

			return nil
		})
	})

	t.Run("delete removes an invitation of any age and says whether there was one", func(t *testing.T) {
		uow := newUoW(t)
		inv := invitationFor(t, "guest@example.test", contractNow, 24*time.Hour)
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error { return s.Invitations.Save(ctx, inv) })
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if ok, err := s.Invitations.Delete(ctx, inv.Email()); err != nil || !ok {
				t.Errorf("Delete = %v, %v", ok, err)
			}

			if ok, err := s.Invitations.Delete(ctx, inv.Email()); err != nil || ok {
				t.Errorf("second Delete = %v, %v; want false", ok, err)
			}

			return nil
		})
	})

	t.Run("list is oldest first", func(t *testing.T) {
		uow := newUoW(t)
		later := invitationFor(t, "a-later@example.test", contractNow.Add(time.Hour), week)
		earlier := invitationFor(t, "z-earlier@example.test", contractNow, week)
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if err := s.Invitations.Save(ctx, later); err != nil {
				return err
			}

			return s.Invitations.Save(ctx, earlier)
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			list, err := s.Invitations.List(ctx)
			if err != nil || len(list) != 2 || list[0].Email() != earlier.Email() || list[1].Email() != later.Email() {
				t.Errorf("List = %v, %v; want the earlier invitation first", list, err)
			}

			return nil
		})
	})

	t.Run("a rolled back invitation does not exist", func(t *testing.T) {
		uow := newUoW(t)
		inv := invitationFor(t, "guest@example.test", contractNow, week)
		_ = do(t, uow, func(ctx context.Context, s port.Stores) error {
			if err := s.Invitations.Save(ctx, inv); err != nil {
				return err
			}

			return errContractRollback
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if _, err := s.Invitations.FindActive(ctx, inv.Email(), contractNow); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("FindActive after the rollback = %v", err)
			}

			return nil
		})
	})

	t.Run("of many concurrent registrations one gets the invitation", func(t *testing.T) {
		uow := newUoW(t)
		inv := invitationFor(t, "race@example.test", contractNow, week)
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error { return s.Invitations.Save(ctx, inv) })

		const workers = 8

		won := make([]bool, workers)

		var wg sync.WaitGroup
		for i := range won {
			wg.Add(1)
			go func() {
				defer wg.Done()

				err := uow.Do(context.Background(), func(ctx context.Context, s port.Stores) error {
					var err error

					won[i], err = s.Invitations.Consume(ctx, inv.Email(), contractNow)

					return err
				})
				if err != nil {
					t.Errorf("worker %d: %v", i, err)
				}
			}()
		}

		wg.Wait()

		n := 0

		for _, ok := range won {
			if ok {
				n++
			}
		}

		if n != 1 {
			t.Errorf("%d registrations used the invitation, want exactly 1", n)
		}
	})
}

func findByEmailContract(t *testing.T, newUoW NewUnitOfWork) {
	t.Run("a user is found by the address and a stranger is not", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		user := seedUser(t, uow, f, "Alice@Example.test")
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			got, err := s.Users.FindByEmail(ctx, user.Email())
			if err != nil || got.ID() != user.ID() {
				t.Errorf("FindByEmail = %v, %v", got, err)
			}

			other, _ := identity.ParseEmail("nobody@example.test")
			if _, err := s.Users.FindByEmail(ctx, other); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("FindByEmail of a stranger = %v, want ErrNotFound", err)
			}

			return nil
		})
	})
}
