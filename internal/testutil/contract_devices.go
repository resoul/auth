package testutil

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/deviceauth"
)

func deviceContract(t *testing.T, newUoW NewUnitOfWork) {
	t.Run("a request is stored and read back with everything it holds", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		req := f.DeviceRequest(DeviceSpec{DeviceName: "Office laptop"})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error { return s.Devices.Create(ctx, req) })
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			got, err := s.Devices.GetForUpdate(ctx, req.ID())
			if err != nil || !reflect.DeepEqual(got.Record(), req.Record()) {
				t.Errorf("GetForUpdate = %+v, %v; want %+v", got, err, req.Record())
			}

			plain, err := s.Devices.Get(ctx, req.ID())
			if err != nil || !reflect.DeepEqual(plain.Record(), req.Record()) {
				t.Errorf("Get = %+v, %v; want %+v", plain, err, req.Record())
			}

			return nil
		})
	})

	t.Run("an unknown request is not found", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		ghost := f.DeviceRequest(DeviceSpec{})

		err := do(t, uow, func(ctx context.Context, s port.Stores) error {
			if _, err := s.Devices.GetForUpdate(ctx, ghost.ID()); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("GetForUpdate = %v, want ErrNotFound", err)
			}

			if _, err := s.Devices.Get(ctx, ghost.ID()); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("Get = %v, want ErrNotFound", err)
			}

			if err := s.Devices.Save(ctx, ghost); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("Save = %v, want ErrNotFound", err)
			}

			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("approval, a wrong code and redemption are stored", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		user := f.User(UserSpec{})
		sess := f.Session(SessionSpec{User: user})
		req := f.DeviceRequest(DeviceSpec{})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if _, _, err := s.Users.Ensure(ctx, user); err != nil {
				return err
			}

			if err := s.Sessions.Create(ctx, sess); err != nil {
				return err
			}

			return s.Devices.Create(ctx, req)
		})

		step := func(name string, fn func(r *deviceauth.Request) error, want deviceauth.State, attempts int) {
			t.Helper()
			mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
				r, err := s.Devices.GetForUpdate(ctx, req.ID())
				if err != nil {
					return err
				}

				_ = fn(r) // a wrong code is an expected refusal that still changes the request

				return s.Devices.Save(ctx, r)
			})
			mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
				r, err := s.Devices.GetForUpdate(ctx, req.ID())
				if err != nil || r.State() != want || r.Attempts() != attempts {
					t.Errorf("%s: state %v attempts %d (%v), want %s and %d", name, r.State(), r.Attempts(), err, want, attempts)
				}

				return nil
			})
		}
		step("a wrong code", func(r *deviceauth.Request) error {
			return r.Approve(contractNow, user.ID(), sess.ID(), "000000")
		}, deviceauth.StatePending, 1)
		step("approval", func(r *deviceauth.Request) error {
			return r.Approve(contractNow, user.ID(), sess.ID(), "123456")
		}, deviceauth.StateApproved, 1)
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			r, err := s.Devices.GetForUpdate(ctx, req.ID())
			if err != nil || r.UserID() != user.ID() || r.ApproverSessionID() != sess.ID() {
				t.Errorf("approver = %v, %v (%v)", r.UserID(), r.ApproverSessionID(), err)
			}

			return nil
		})
		step("redemption", func(r *deviceauth.Request) error {
			return r.Redeem(contractNow, SecretHash("poll-secret"), BindingHash(DefaultBindingSecret))
		}, deviceauth.StateRedeemed, 1)
	})

	t.Run("a refused request is stored as denied", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		req := f.DeviceRequest(DeviceSpec{})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error { return s.Devices.Create(ctx, req) })
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			r, err := s.Devices.GetForUpdate(ctx, req.ID())
			if err != nil {
				return err
			}

			if err := r.Deny(contractNow); err != nil {
				return err
			}

			return s.Devices.Save(ctx, r)
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			r, err := s.Devices.GetForUpdate(ctx, req.ID())
			if err != nil || r.State() != deviceauth.StateDenied {
				t.Errorf("state %v (%v), want denied", r.State(), err)
			}

			return nil
		})
	})

	t.Run("deleting the approving user removes the request, ending their session keeps it", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		user := f.User(UserSpec{})
		sess := f.Session(SessionSpec{User: user})

		req := f.DeviceRequest(DeviceSpec{})
		if err := req.Approve(contractNow, user.ID(), sess.ID(), "123456"); err != nil {
			t.Fatal(err)
		}

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if _, _, err := s.Users.Ensure(ctx, user); err != nil {
				return err
			}

			if err := s.Sessions.Create(ctx, sess); err != nil {
				return err
			}

			return s.Devices.Create(ctx, req)
		})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error { return s.Users.Delete(ctx, user.ID()) })

		err := do(t, uow, func(ctx context.Context, s port.Stores) error {
			_, err := s.Devices.GetForUpdate(ctx, req.ID())
			return err
		})
		if !errors.Is(err, port.ErrNotFound) {
			t.Errorf("after the user was deleted: %v, want ErrNotFound", err)
		}
	})

	t.Run("a rolled back request does not exist", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		req := f.DeviceRequest(DeviceSpec{})
		_ = do(t, uow, func(ctx context.Context, s port.Stores) error {
			if err := s.Devices.Create(ctx, req); err != nil {
				return err
			}

			return errContractRollback
		})

		err := do(t, uow, func(ctx context.Context, s port.Stores) error {
			_, err := s.Devices.GetForUpdate(ctx, req.ID())
			return err
		})
		if !errors.Is(err, port.ErrNotFound) {
			t.Errorf("after the rollback: %v", err)
		}
	})

	t.Run("of many concurrent redemptions exactly one wins, and of many approvals too", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		user := f.User(UserSpec{})
		sess := f.Session(SessionSpec{User: user})
		req := f.DeviceRequest(DeviceSpec{})

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			if _, _, err := s.Users.Ensure(ctx, user); err != nil {
				return err
			}

			if err := s.Sessions.Create(ctx, sess); err != nil {
				return err
			}

			return s.Devices.Create(ctx, req)
		})

		race := func(name string, act func(r *deviceauth.Request) error) {
			const workers = 8

			won := make([]bool, workers)

			var wg sync.WaitGroup
			for i := range won {
				wg.Add(1)
				go func() {
					defer wg.Done()

					err := uow.Do(context.Background(), func(ctx context.Context, s port.Stores) error {
						r, err := s.Devices.GetForUpdate(ctx, req.ID())
						if err != nil {
							return err
						}

						if act(r) != nil {
							return nil
						}

						won[i] = true

						return s.Devices.Save(ctx, r)
					})
					if err != nil {
						t.Errorf("%s worker %d: %v", name, i, err)
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
				t.Errorf("%d %ss succeeded, want exactly 1", n, name)
			}
		}
		race("approval", func(r *deviceauth.Request) error { return r.Approve(contractNow, user.ID(), sess.ID(), "123456") })
		race("redemption", func(r *deviceauth.Request) error {
			return r.Redeem(contractNow.Add(time.Second), SecretHash("poll-secret"), BindingHash(DefaultBindingSecret))
		})
	})
}
