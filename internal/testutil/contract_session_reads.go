package testutil

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/session"
)

// sessionReadContract checks the read-only session and user lookups that the access check
// and the session API use.
func sessionReadContract(t *testing.T, newUoW NewUnitOfWork) {
	t.Run("Get reads a session without locking or changing it", func(t *testing.T) {
		fx := newSessionFixture(t, newUoW)
		absent := fx.f.Session(SessionSpec{User: fx.user})
		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			got, err := s.Sessions.Get(ctx, fx.sess.ID())
			if err != nil || !reflect.DeepEqual(got.Record(), fx.sess.Record()) {
				t.Errorf("Get = %+v, %v", got, err)
			}
			if _, err := s.Sessions.Get(ctx, absent.ID()); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("Get of a missing session = %v, want ErrNotFound", err)
			}
			return nil
		})
	})

	t.Run("ListActive returns the user's live sessions, newest activity first", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		alice, bob := seedUser(t, uow, f, ""), seedUser(t, uow, f, "")
		create := func(user SessionSpec) *session.Session {
			sess := f.Session(user)
			mustDo(t, uow, func(ctx context.Context, s port.Stores) error { return s.Sessions.Create(ctx, sess) })
			return sess
		}
		first := create(SessionSpec{User: alice})
		f.Clock.Advance(time.Hour)
		second := create(SessionSpec{User: alice})
		f.Clock.Advance(time.Hour)
		third := create(SessionSpec{User: alice})
		revoked := create(SessionSpec{User: alice})
		create(SessionSpec{User: bob})
		f.Clock.Advance(time.Hour)

		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			sess, err := s.Sessions.GetForUpdate(ctx, first.ID())
			if err != nil {
				return err
			}
			if err := sess.Touch(f.Clock.Now(), session.DefaultPolicy()); err != nil {
				return err
			}
			if err := s.Sessions.Save(ctx, sess); err != nil {
				return err
			}
			gone, err := s.Sessions.GetForUpdate(ctx, revoked.ID())
			if err != nil {
				return err
			}
			gone.Revoke(f.Clock.Now())
			return s.Sessions.Save(ctx, gone)
		})

		ids := func(list []*session.Session) []session.ID {
			var out []session.ID
			for _, s := range list {
				out = append(out, s.ID())
			}
			return out
		}
		list := func(now time.Time, limit int) []*session.Session {
			var got []*session.Session
			mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
				var err error
				got, err = s.Sessions.ListActive(ctx, alice.ID(), now, limit)
				return err
			})
			return got
		}

		now := f.Clock.Now()
		got := list(now, 10)
		// first was touched last; third and revoked started together, and the revoked one is gone.
		if want := []session.ID{first.ID(), third.ID(), second.ID()}; !reflect.DeepEqual(ids(got), want) {
			t.Errorf("ListActive = %v, want %v", ids(got), want)
		}
		if !reflect.DeepEqual(got[0].Record(), loadSession(t, uow, first.ID()).Record()) {
			t.Error("a listed session differs from the stored one")
		}
		if got := ids(list(now, 2)); len(got) != 2 || got[0] != first.ID() || got[1] != third.ID() {
			t.Errorf("ListActive with a limit of 2 = %v", got)
		}
		if got := list(now, 0); len(got) != 0 {
			t.Errorf("ListActive with a limit of 0 = %d sessions", len(got))
		}
		// Idle: shortly before the touched session's idle limit, the others have passed theirs.
		if got := ids(list(now.Add(30*24*time.Hour-30*time.Minute), 10)); len(got) != 1 || got[0] != first.ID() {
			t.Errorf("near the idle limit = %v, want only the touched session", got)
		}
		// Absolute: nothing lives past 90 days.
		if got := list(now.Add(91*24*time.Hour), 10); len(got) != 0 {
			t.Errorf("after 91 days = %d sessions", len(got))
		}
	})

	t.Run("a user is read by ID", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		user := seedUser(t, uow, f, "alice@example.test")
		absent := f.User(UserSpec{})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
			got, err := s.Users.Get(ctx, user.ID())
			if err != nil || !reflect.DeepEqual(got.Record(), user.Record()) {
				t.Errorf("Get = %+v, %v", got, err)
			}
			if _, err := s.Users.Get(ctx, absent.ID()); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("Get of a missing user = %v, want ErrNotFound", err)
			}
			return nil
		})
	})
}
