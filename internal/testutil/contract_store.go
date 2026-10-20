package testutil

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/authflow"
	"go.airlance.org/auth/internal/domain/identity"
)

// NewUnitOfWork returns an empty, isolated UnitOfWork for one subtest. Adapters
// pass their own constructor, so memory and PostgreSQL face the same contract.
type NewUnitOfWork func(t *testing.T) port.UnitOfWork

var errContractRollback = errors.New("contract rollback")

// RunStoreContract checks the repository ports of an adapter: flows, users,
// recognized clients, sessions and refresh tokens, including rollback, token
// invariants and concurrent registration.
func RunStoreContract(t *testing.T, newUoW NewUnitOfWork) {
	t.Helper()
	t.Run("flows", func(t *testing.T) { flowContract(t, newUoW) })
	t.Run("users", func(t *testing.T) { userContract(t, newUoW) })
	t.Run("recognized clients", func(t *testing.T) { recognizedContract(t, newUoW) })
	t.Run("sessions", func(t *testing.T) { sessionContract(t, newUoW) })
	t.Run("refresh tokens", func(t *testing.T) { tokenContract(t, newUoW) })
	t.Run("audit", func(t *testing.T) { auditContract(t, newUoW) })
	t.Run("outbox", func(t *testing.T) { outboxContract(t, newUoW) })
	t.Run("session reads", func(t *testing.T) { sessionReadContract(t, newUoW) })
	t.Run("passkeys", func(t *testing.T) { passkeyContract(t, newUoW) })
	t.Run("invitations", func(t *testing.T) { invitationContract(t, newUoW) })
	t.Run("find by email", func(t *testing.T) { findByEmailContract(t, newUoW) })
	t.Run("admin", func(t *testing.T) { adminContract(t, newUoW) })
	t.Run("device requests", func(t *testing.T) { deviceContract(t, newUoW) })
}

var contractNow = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func do(t *testing.T, uow port.UnitOfWork, fn func(ctx context.Context, s port.Stores) error) error {
	t.Helper()
	return uow.Do(context.Background(), fn)
}

func mustDo(t *testing.T, uow port.UnitOfWork, fn func(ctx context.Context, s port.Stores) error) {
	t.Helper()

	if err := do(t, uow, fn); err != nil {
		t.Fatalf("transaction failed: %v", err)
	}
}

func flowContract(t *testing.T, newUoW NewUnitOfWork) {
	binding := BindingHash(DefaultBindingSecret)
	policy := authflow.DefaultPolicy()

	t.Run("created flow is read back unchanged", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		flow := f.Flow(FlowSpec{})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error { return s.Flows.Create(ctx, flow) })

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			got, err := s.Flows.GetForUpdate(ctx, flow.ID())
			if err != nil {
				return err
			}

			if !reflect.DeepEqual(got.Record(), flow.Record()) {
				t.Errorf("stored record differs:\n got %+v\nwant %+v", got.Record(), flow.Record())
			}

			return nil
		})
	})

	t.Run("a change_email flow is read back with its user", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		user := seedUser(t, uow, f, "")
		flow := f.Flow(FlowSpec{Purpose: authflow.PurposeChangeEmail, UserID: user.ID()})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error { return s.Flows.Create(ctx, flow) })

		for name, load := range map[string]func(context.Context, port.Stores) (*authflow.Flow, error){
			"GetForUpdate": func(ctx context.Context, s port.Stores) (*authflow.Flow, error) {
				return s.Flows.GetForUpdate(ctx, flow.ID())
			},
			"Get": func(ctx context.Context, s port.Stores) (*authflow.Flow, error) { return s.Flows.Get(ctx, flow.ID()) },
		} {
			mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
				got, err := load(ctx, s)
				if err != nil {
					return err
				}

				if got.UserID() != user.ID() || got.Purpose() != authflow.PurposeChangeEmail || !reflect.DeepEqual(got.Record(), flow.Record()) {
					t.Errorf("%s: stored record differs:\n got %+v\nwant %+v", name, got.Record(), flow.Record())
				}

				return nil
			})
		}
	})

	t.Run("Get reads without changing anything", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		flow := f.Flow(FlowSpec{})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error { return s.Flows.Create(ctx, flow) })
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			got, err := s.Flows.Get(ctx, flow.ID())
			if err != nil {
				return err
			}

			if !reflect.DeepEqual(got.Record(), flow.Record()) {
				t.Errorf("Get differs:\n got %+v\nwant %+v", got.Record(), flow.Record())
			}

			other := f.Flow(FlowSpec{})
			if _, err := s.Flows.Get(ctx, other.ID()); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("Get of a missing flow = %v, want ErrNotFound", err)
			}

			return nil
		})
	})

	t.Run("missing flow", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		flow := f.Flow(FlowSpec{})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if _, err := s.Flows.GetForUpdate(ctx, flow.ID()); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("GetForUpdate = %v, want ErrNotFound", err)
			}

			if err := s.Flows.Save(ctx, flow); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("Save = %v, want ErrNotFound", err)
			}

			return nil
		})
	})

	t.Run("duplicate id is rejected", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		flow := f.Flow(FlowSpec{})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error { return s.Flows.Create(ctx, flow) })

		if err := do(t, uow, func(ctx context.Context, s port.Stores) error { return s.Flows.Create(ctx, flow) }); err == nil {
			t.Error("Create accepted a duplicate id")
		}
	})

	t.Run("saved changes persist and rollback discards them", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		flow := f.Flow(FlowSpec{})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error { return s.Flows.Create(ctx, flow) })

		reserve := func(fail bool) {
			_ = do(t, uow, func(ctx context.Context, s port.Stores) error {
				loaded, err := s.Flows.GetForUpdate(ctx, flow.ID())
				if err != nil {
					return err
				}

				if _, err := loaded.Reserve(contractNow, authflow.PurposeLogin, binding, policy); err != nil {
					return err
				}

				if err := s.Flows.Save(ctx, loaded); err != nil {
					return err
				}

				if fail {
					return errContractRollback
				}

				return nil
			})
		}
		attempts := func() int {
			var n int

			mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
				loaded, err := s.Flows.GetForUpdate(ctx, flow.ID())
				if err == nil {
					n = loaded.Attempts()
				}

				return err
			})

			return n
		}

		reserve(true)

		if got := attempts(); got != 0 {
			t.Errorf("attempts = %d after a rolled back transaction", got)
		}

		reserve(false)

		if got := attempts(); got != 1 {
			t.Errorf("attempts = %d after a committed transaction", got)
		}
	})

	t.Run("closed flow keeps no salt", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		flow := f.Flow(FlowSpec{})

		attempt, err := flow.Reserve(contractNow, authflow.PurposeLogin, binding, policy)
		if err != nil {
			t.Fatal(err)
		}

		if err := flow.Accept(attempt, contractNow); err != nil {
			t.Fatal(err)
		}

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error { return s.Flows.Create(ctx, flow) })
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			got, err := s.Flows.GetForUpdate(ctx, flow.ID())
			if err != nil {
				return err
			}

			if got.State() != authflow.StateConsumed || len(got.Salt()) != 0 {
				t.Errorf("state=%s salt=%d bytes", got.State(), len(got.Salt()))
			}

			return nil
		})
	})
}

func userContract(t *testing.T, newUoW NewUnitOfWork) {
	t.Run("ensure creates once per email", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		first := f.User(UserSpec{Email: "alice@example.test"})
		second := f.User(UserSpec{Email: "alice@example.test"})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			u1, created1, err := s.Users.Ensure(ctx, first)
			if err != nil || !created1 || u1.ID() != first.ID() {
				t.Errorf("first Ensure = %v, %v, %v", u1, created1, err)
			}

			return nil
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			u2, created2, err := s.Users.Ensure(ctx, second)
			if err != nil || created2 || u2.ID() != first.ID() {
				t.Errorf("second Ensure = %v, %v, %v; want the first user", u2, created2, err)
			}

			return nil
		})
	})

	t.Run("a user can be read for update, and a missing one is not found", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		alice := seedUser(t, uow, f, "")
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			got, err := s.Users.GetForUpdate(ctx, alice.ID())
			if err != nil || got.ID() != alice.ID() || got.Email() != alice.Email() {
				t.Errorf("GetForUpdate = %+v, %v", got, err)
			}

			if _, err := s.Users.GetForUpdate(ctx, f.User(UserSpec{}).ID()); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("GetForUpdate of a missing user = %v, want ErrNotFound", err)
			}

			return nil
		})
	})

	t.Run("rolled back user does not exist", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		user := f.User(UserSpec{})
		_ = do(t, uow, func(ctx context.Context, s port.Stores) error {
			if _, _, err := s.Users.Ensure(ctx, user); err != nil {
				return err
			}

			return errContractRollback
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			_, created, err := s.Users.Ensure(ctx, user)
			if err != nil || !created {
				t.Errorf("Ensure after rollback = created %v, %v; want created", created, err)
			}

			return nil
		})
	})

	t.Run("concurrent ensure yields one user", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)

		const workers = 8

		candidates := make([]*identity.User, workers)
		for i := range candidates {
			candidates[i] = f.User(UserSpec{Email: "race@example.test"})
		}

		ids := make([]identity.UserID, workers)
		created := make([]bool, workers)

		var wg sync.WaitGroup
		for i := range candidates {
			wg.Add(1)
			go func() {
				defer wg.Done()

				err := uow.Do(context.Background(), func(ctx context.Context, s port.Stores) error {
					u, c, err := s.Users.Ensure(ctx, candidates[i])
					if err != nil {
						return err
					}

					ids[i], created[i] = u.ID(), c

					return nil
				})
				if err != nil {
					t.Errorf("worker %d: %v", i, err)
				}
			}()
		}

		wg.Wait()

		creators := 0

		for i := range ids {
			if ids[i] != ids[0] {
				t.Errorf("worker %d got user %s, worker 0 got %s", i, ids[i], ids[0])
			}

			if created[i] {
				creators++
			}
		}

		if creators != 1 {
			t.Errorf("%d workers created the user, want exactly 1", creators)
		}
	})

	t.Run("change email moves the account and frees the old address", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		user := seedUser(t, uow, f, "old@example.test")
		later := contractNow.Add(48 * time.Hour)

		next, err := identity.ParseEmail("new@example.test")
		if err != nil {
			t.Fatal(err)
		}

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			moved, err := s.Users.Get(ctx, user.ID())
			if err != nil {
				return err
			}

			if err := moved.ChangeEmail(next, later); err != nil {
				return err
			}

			return s.Users.ChangeEmail(ctx, moved)
		})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			got, err := s.Users.Get(ctx, user.ID())
			if err != nil {
				return err
			}

			if got.Email() != next || !got.EmailVerifiedAt().Equal(later) || !got.UpdatedAt().Equal(later) || !got.CreatedAt().Equal(contractNow) {
				t.Errorf("stored user = %+v", got.Record())
			}
			// The old address belongs to nobody now: a new user can have it.
			_, created, err := s.Users.Ensure(ctx, f.User(UserSpec{Email: "old@example.test"}))
			if err != nil || !created {
				t.Errorf("Ensure of the freed address = created %v, %v", created, err)
			}
			// And the new one is the account's: Ensure finds it.
			same, created, err := s.Users.Ensure(ctx, f.User(UserSpec{Email: "new@example.test"}))
			if err != nil || created || same.ID() != user.ID() {
				t.Errorf("Ensure of the new address = %v, created %v, %v; want the moved account", same, created, err)
			}

			return nil
		})
	})

	t.Run("change email refuses an address another user has and stays usable", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		mover := seedUser(t, uow, f, "mover@example.test")
		owner := seedUser(t, uow, f, "owner@example.test")
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			moved, err := s.Users.Get(ctx, mover.ID())
			if err != nil {
				return err
			}

			if err := moved.ChangeEmail(owner.Email(), contractNow.Add(time.Hour)); err != nil {
				return err
			}

			if err := s.Users.ChangeEmail(ctx, moved); !errors.Is(err, port.ErrEmailTaken) {
				t.Errorf("ChangeEmail = %v, want ErrEmailTaken", err)
			}
			// The refusal does not poison the transaction: the caller can still read and write.
			if got, err := s.Users.Get(ctx, mover.ID()); err != nil || got.Email() != mover.Email() {
				t.Errorf("Get after the refusal = %v, %v; want the unchanged user", got, err)
			}

			return nil
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			for _, u := range []*identity.User{mover, owner} {
				got, err := s.Users.Get(ctx, u.ID())
				if err != nil || got.Email() != u.Email() {
					t.Errorf("user %s = %v, %v; want unchanged", u.ID(), got, err)
				}
			}

			return nil
		})
	})

	t.Run("change email of a missing user", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		ghost := f.User(UserSpec{})

		next, _ := identity.ParseEmail("next@example.test")
		if err := ghost.ChangeEmail(next, contractNow.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}

		err := do(t, uow, func(ctx context.Context, s port.Stores) error { return s.Users.ChangeEmail(ctx, ghost) })
		if !errors.Is(err, port.ErrNotFound) {
			t.Errorf("ChangeEmail = %v, want ErrNotFound", err)
		}
	})

	t.Run("rolled back change email is invisible", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		user := seedUser(t, uow, f, "stay@example.test")
		next, _ := identity.ParseEmail("gone@example.test")
		_ = do(t, uow, func(ctx context.Context, s port.Stores) error {
			moved, err := s.Users.Get(ctx, user.ID())
			if err != nil {
				return err
			}

			if err := moved.ChangeEmail(next, contractNow.Add(time.Hour)); err != nil {
				return err
			}

			if err := s.Users.ChangeEmail(ctx, moved); err != nil {
				return err
			}

			return errContractRollback
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			got, err := s.Users.Get(ctx, user.ID())
			if err != nil || got.Email() != user.Email() {
				t.Errorf("user after the rollback = %v, %v", got, err)
			}

			if _, created, err := s.Users.Ensure(ctx, f.User(UserSpec{Email: "gone@example.test"})); err != nil || !created {
				t.Errorf("Ensure of the address of the rolled back change = created %v, %v", created, err)
			}

			return nil
		})
	})

	t.Run("two accounts moving to one address at once: one wins", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)

		const movers = 6

		users := make([]*identity.User, movers)
		for i := range users {
			users[i] = seedUser(t, uow, f, "")
		}

		target, _ := identity.ParseEmail("target@example.test")

		errs := make([]error, movers)

		var wg sync.WaitGroup
		for i := range users {
			wg.Add(1)
			go func() {
				defer wg.Done()

				errs[i] = uow.Do(context.Background(), func(ctx context.Context, s port.Stores) error {
					moved, err := s.Users.Get(ctx, users[i].ID())
					if err != nil {
						return err
					}

					if err := moved.ChangeEmail(target, contractNow.Add(time.Hour)); err != nil {
						return err
					}

					return s.Users.ChangeEmail(ctx, moved)
				})
			}()
		}

		wg.Wait()

		won := 0

		for i, err := range errs {
			switch {
			case err == nil:
				won++
			case !errors.Is(err, port.ErrEmailTaken):
				t.Errorf("mover %d: %v, want success or ErrEmailTaken", i, err)
			}
		}

		if won != 1 {
			t.Errorf("%d accounts got the address, want exactly 1", won)
		}
	})
}

func recognizedContract(t *testing.T, newUoW NewUnitOfWork) {
	type fixture struct {
		uow  port.UnitOfWork
		f    *Factory
		user *identity.User
	}

	setup := func(t *testing.T) fixture {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		user := f.User(UserSpec{})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			_, _, err := s.Users.Ensure(ctx, user)
			return err
		})

		return fixture{uow, f, user}
	}
	register := func(t *testing.T, fx fixture, secret string, at time.Time) *identity.RecognizedClient {
		t.Helper()
		fx.f.Clock.Set(at)
		candidate := fx.f.RecognizedClient(RecognizedSpec{User: fx.user, BindingSecret: secret})

		var stored *identity.RecognizedClient

		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			var err error

			stored, err = s.Recognized.Register(ctx, candidate)

			return err
		})

		return stored
	}
	findActive := func(t *testing.T, fx fixture, email identity.Email, secret string, at time.Time) (*identity.RecognizedClient, error) {
		t.Helper()

		var found *identity.RecognizedClient

		err := do(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			var err error

			found, err = s.Recognized.FindActive(ctx, email, BindingHash(secret), at)

			return err
		})

		return found, err
	}
	extend := func(t *testing.T, fx fixture, secret string, at time.Time) error {
		t.Helper()

		return do(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			return s.Recognized.Extend(ctx, fx.user.ID(), BindingHash(secret), at)
		})
	}
	revoke := func(t *testing.T, fx fixture, secret string, at time.Time) {
		t.Helper()
		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			return s.Recognized.Revoke(ctx, fx.user.ID(), BindingHash(secret), at)
		})
	}

	t.Run("registered client is found by email and binding", func(t *testing.T) {
		fx := setup(t)
		c := register(t, fx, "device-a", contractNow)

		got, err := findActive(t, fx, fx.user.Email(), "device-a", contractNow)
		if err != nil || got.ID() != c.ID() || got.UserID() != fx.user.ID() {
			t.Fatalf("FindActive = %v, %v", got, err)
		}

		if !got.ExpiresAt().Equal(contractNow.Add(identity.RecognitionTTL)) {
			t.Errorf("ExpiresAt = %v", got.ExpiresAt())
		}
	})

	t.Run("lookup needs the same binding, email and an active record", func(t *testing.T) {
		fx := setup(t)
		c := register(t, fx, "device-a", contractNow)

		other := fx.f.User(UserSpec{Email: "someone-else@example.test"})
		for name, tc := range map[string]struct {
			email  identity.Email
			secret string
			at     time.Time
		}{
			"other binding": {fx.user.Email(), "device-b", contractNow},
			"other email":   {other.Email(), "device-a", contractNow},
			"at expiry":     {fx.user.Email(), "device-a", c.ExpiresAt()},
		} {
			if got, err := findActive(t, fx, tc.email, tc.secret, tc.at); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("%s: FindActive = %v, %v; want ErrNotFound", name, got, err)
			}
		}

		revoke(t, fx, "device-a", contractNow.Add(time.Hour))

		if _, err := findActive(t, fx, fx.user.Email(), "device-a", contractNow.Add(2*time.Hour)); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("revoked record found: %v", err)
		}
	})

	t.Run("registering the pair again with a new address moves the record to it", func(t *testing.T) {
		for name, revokeFirst := range map[string]bool{"revoked by the change": true, "still active": false} {
			t.Run(name, func(t *testing.T) {
				fx := setup(t)
				first := register(t, fx, "device-a", contractNow)
				changedAt := contractNow.Add(time.Hour)

				if revokeFirst {
					revoke(t, fx, "device-a", changedAt)
				}

				moved, err := identity.ParseEmail("moved@example.test")
				if err != nil {
					t.Fatal(err)
				}

				later := changedAt.Add(time.Minute)
				fx.f.Clock.Set(later)
				candidate := fx.f.RecognizedClient(RecognizedSpec{User: fx.user, BindingSecret: "device-a", Email: moved})

				var stored *identity.RecognizedClient

				mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
					var err error

					stored, err = s.Recognized.Register(ctx, candidate)

					return err
				})

				if stored.ID() != first.ID() || stored.Email() != moved {
					t.Errorf("Register = id %s email %s, want id %s email %s", stored.ID(), stored.Email(), first.ID(), moved)
				}

				if got, err := findActive(t, fx, moved, "device-a", later); err != nil || got.ID() != first.ID() {
					t.Errorf("FindActive(new address) = %+v, %v", got, err)
				}

				if got, err := findActive(t, fx, fx.user.Email(), "device-a", later); !errors.Is(err, port.ErrNotFound) {
					t.Errorf("FindActive(old address) = %+v, %v; want ErrNotFound", got, err)
				}
			})
		}
	})

	t.Run("registering the same pair again keeps one record", func(t *testing.T) {
		fx := setup(t)
		first := register(t, fx, "device-a", contractNow)
		later := contractNow.Add(24 * time.Hour)
		second := register(t, fx, "device-a", later)

		if second.ID() != first.ID() {
			t.Errorf("second Register returned a new id %s, want %s", second.ID(), first.ID())
		}

		got, err := findActive(t, fx, fx.user.Email(), "device-a", later)
		if err != nil || got.ID() != first.ID() || !got.VerifiedAt().Equal(later) || !got.ExpiresAt().Equal(later.Add(identity.RecognitionTTL)) {
			t.Errorf("FindActive = %+v, %v", got, err)
		}
	})

	t.Run("verify revives revoked and expired records", func(t *testing.T) {
		fx := setup(t)
		first := register(t, fx, "device-a", contractNow)
		revoke(t, fx, "device-a", contractNow.Add(time.Hour))

		again := register(t, fx, "device-a", contractNow.Add(2*time.Hour))
		if again.ID() != first.ID() || !again.RevokedAt().IsZero() {
			t.Errorf("revoked record not revived: %+v", again.Record())
		}

		expiredAt := contractNow.Add(identity.RecognitionTTL + 2*time.Hour + time.Hour)

		revived := register(t, fx, "device-a", expiredAt)
		if _, err := findActive(t, fx, fx.user.Email(), "device-a", expiredAt); err != nil || revived.ID() != first.ID() {
			t.Errorf("expired record not revived: %v", err)
		}
	})

	t.Run("refresh extends only an active record", func(t *testing.T) {
		fx := setup(t)
		c := register(t, fx, "device-a", contractNow)

		later := contractNow.Add(30 * 24 * time.Hour)
		if err := extend(t, fx, "device-a", later); err != nil {
			t.Fatalf("Extend: %v", err)
		}

		got, err := findActive(t, fx, fx.user.Email(), "device-a", later)
		if err != nil || !got.ExpiresAt().Equal(later.Add(identity.RecognitionTTL)) || !got.VerifiedAt().Equal(c.VerifiedAt()) {
			t.Errorf("after Extend: %+v, %v", got, err)
		}

		if err := extend(t, fx, "unknown-device", later); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("Extend of a missing record = %v, want ErrNotFound", err)
		}

		revoke(t, fx, "device-a", later.Add(time.Hour))

		if err := extend(t, fx, "device-a", later.Add(2*time.Hour)); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("Extend of a revoked record = %v, want ErrNotFound", err)
		}

		if _, err := findActive(t, fx, fx.user.Email(), "device-a", later.Add(2*time.Hour)); !errors.Is(err, port.ErrNotFound) {
			t.Error("Extend restored a revoked record")
		}
	})

	t.Run("expired record is not extended", func(t *testing.T) {
		fx := setup(t)

		c := register(t, fx, "device-a", contractNow)
		if err := extend(t, fx, "device-a", c.ExpiresAt()); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("Extend at expiry = %v, want ErrNotFound", err)
		}
	})

	t.Run("revoke affects one binding and is idempotent", func(t *testing.T) {
		fx := setup(t)
		register(t, fx, "device-a", contractNow)
		register(t, fx, "device-b", contractNow)
		revoke(t, fx, "device-a", contractNow.Add(time.Hour))
		revoke(t, fx, "device-a", contractNow.Add(2*time.Hour))
		revoke(t, fx, "never-registered", contractNow.Add(time.Hour))

		at := contractNow.Add(3 * time.Hour)
		if _, err := findActive(t, fx, fx.user.Email(), "device-a", at); !errors.Is(err, port.ErrNotFound) {
			t.Error("revoked binding is still active")
		}

		if _, err := findActive(t, fx, fx.user.Email(), "device-b", at); err != nil {
			t.Errorf("another binding was affected: %v", err)
		}
	})

	t.Run("revoke all ends every binding of the user only", func(t *testing.T) {
		fx := setup(t)
		other := fx.f.User(UserSpec{Email: "other@example.test"})
		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			_, _, err := s.Users.Ensure(ctx, other)
			return err
		})
		register(t, fx, "device-a", contractNow)
		register(t, fx, "device-b", contractNow)
		otherClient := fx.f.RecognizedClient(RecognizedSpec{User: other, BindingSecret: "device-a"})
		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			_, err := s.Recognized.Register(ctx, otherClient)
			return err
		})

		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			return s.Recognized.RevokeAll(ctx, fx.user.ID(), contractNow.Add(time.Hour))
		})

		at := contractNow.Add(2 * time.Hour)
		for _, secret := range []string{"device-a", "device-b"} {
			if _, err := findActive(t, fx, fx.user.Email(), secret, at); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("%s is still active after RevokeAll", secret)
			}
		}

		if _, err := findActive(t, fx, other.Email(), "device-a", at); err != nil {
			t.Errorf("another user's record was revoked: %v", err)
		}
	})

	t.Run("rolled back registration is invisible", func(t *testing.T) {
		fx := setup(t)
		candidate := fx.f.RecognizedClient(RecognizedSpec{User: fx.user})

		_ = do(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			if _, err := s.Recognized.Register(ctx, candidate); err != nil {
				return err
			}

			return errContractRollback
		})
		if _, err := findActive(t, fx, fx.user.Email(), DefaultBindingSecret, contractNow); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("rolled back record found: %v", err)
		}
	})

	t.Run("concurrent registration of one pair yields one record", func(t *testing.T) {
		fx := setup(t)

		const workers = 8

		candidates := make([]*identity.RecognizedClient, workers)
		for i := range candidates {
			candidates[i] = fx.f.RecognizedClient(RecognizedSpec{User: fx.user})
		}

		ids := make([]identity.RecognizedClientID, workers)

		var wg sync.WaitGroup
		for i := range candidates {
			wg.Add(1)
			go func() {
				defer wg.Done()

				err := fx.uow.Do(context.Background(), func(ctx context.Context, s port.Stores) error {
					c, err := s.Recognized.Register(ctx, candidates[i])
					if err == nil {
						ids[i] = c.ID()
					}

					return err
				})
				if err != nil {
					t.Errorf("worker %d: %v", i, err)
				}
			}()
		}

		wg.Wait()

		for i := range ids {
			if ids[i] != ids[0] {
				t.Errorf("worker %d got record %s, worker 0 got %s", i, ids[i], ids[0])
			}
		}
	})
}

func auditContract(t *testing.T, newUoW NewUnitOfWork) {
	t.Run("a valid event is recorded with and without references", func(t *testing.T) {
		fx := newSessionFixture(t, newUoW)
		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			if err := s.Audit.Record(ctx, port.AuditEvent{
				Type: port.AuditLoginSucceeded, Result: port.AuditSuccess, UserID: fx.user.ID(), SessionID: fx.sess.ID(), At: contractNow,
				Fields: map[string]string{"method": "otp", "new_user": "true"},
			}); err != nil {
				return err
			}

			return s.Audit.Record(ctx, port.AuditEvent{Type: port.AuditAllSessionsRevoked, Result: port.AuditSuccess, At: contractNow})
		})
	})

	t.Run("an event that could hold personal data is refused", func(t *testing.T) {
		fx := newSessionFixture(t, newUoW)

		err := do(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			return s.Audit.Record(ctx, port.AuditEvent{
				Type: port.AuditLoginSucceeded, Result: port.AuditSuccess, At: contractNow,
				Fields: map[string]string{"reason": "alice@example.test"},
			})
		})
		if err == nil {
			t.Error("Record accepted an email as a field value")
		}
	})
}
