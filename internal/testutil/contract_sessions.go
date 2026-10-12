package testutil

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/domain/session"
	"airlance.org/auth/internal/domain/token"
)

// sessionFixture is a user with one session and its root token, already stored.
type sessionFixture struct {
	uow  port.UnitOfWork
	f    *Factory
	user *identity.User
	sess *session.Session
	root *token.RefreshToken
}

func seedUser(t *testing.T, uow port.UnitOfWork, f *Factory, email string) *identity.User {
	t.Helper()
	user := f.User(UserSpec{Email: email})
	mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
		_, _, err := s.Users.Ensure(ctx, user)
		return err
	})
	return user
}

func seedSession(t *testing.T, uow port.UnitOfWork, f *Factory, user *identity.User) (*session.Session, *token.RefreshToken) {
	t.Helper()
	sess := f.Session(SessionSpec{User: user})
	root, _ := f.RefreshToken(RefreshSpec{Session: sess})
	mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
		if err := s.Sessions.Create(ctx, sess); err != nil {
			return err
		}
		return s.Tokens.Create(ctx, root)
	})
	return sess, root
}

func newSessionFixture(t *testing.T, newUoW NewUnitOfWork) sessionFixture {
	t.Helper()
	uow, f := newUoW(t), NewFactory(t, contractNow)
	user := seedUser(t, uow, f, "")
	sess, root := seedSession(t, uow, f, user)
	return sessionFixture{uow, f, user, sess, root}
}

func loadSession(t *testing.T, uow port.UnitOfWork, id session.ID) *session.Session {
	t.Helper()
	var sess *session.Session
	mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
		var err error
		sess, err = s.Sessions.GetForUpdate(ctx, id)
		return err
	})
	return sess
}

func loadToken(t *testing.T, uow port.UnitOfWork, id token.ID) *token.RefreshToken {
	t.Helper()
	var tok *token.RefreshToken
	mustDo(t, uow, func(ctx context.Context, s port.Stores) error {
		var err error
		tok, err = s.Tokens.GetForUpdate(ctx, id)
		return err
	})
	return tok
}

func sessionContract(t *testing.T, newUoW NewUnitOfWork) {
	t.Run("history tells whether the user has sessions and one from the binding", func(t *testing.T) {
		fx := newSessionFixture(t, newUoW)
		history := func(user *identity.User, binding identity.BindingHash) (h port.SessionHistory) {
			mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
				var err error
				h, err = s.Sessions.History(ctx, user.ID(), binding)
				return err
			})
			return h
		}
		if got := history(fx.user, fx.sess.Binding()); !got.Any || !got.ThisBinding || got.NewClient() {
			t.Errorf("the binding of a kept session: %+v", got)
		}
		other := fx.f.Session(SessionSpec{User: fx.user, BindingSecret: fx.f.RefreshSecret()})
		if got := history(fx.user, other.Binding()); !got.Any || got.ThisBinding || !got.NewClient() {
			t.Errorf("a binding no session has: %+v", got)
		}
		// Ended sessions still count: the client was used.
		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			return s.Sessions.RevokeAllForUser(ctx, fx.user.ID(), contractNow)
		})
		if got := history(fx.user, fx.sess.Binding()); !got.ThisBinding {
			t.Errorf("a revoked session is forgotten: %+v", got)
		}
		// Another user's sessions say nothing; an account without any has no history to compare with.
		stranger := seedUser(t, fx.uow, fx.f, "")
		if got := history(stranger, fx.sess.Binding()); got.Any || got.ThisBinding || got.NewClient() {
			t.Errorf("a user without sessions: %+v", got)
		}
	})

	t.Run("created session is read back unchanged", func(t *testing.T) {
		fx := newSessionFixture(t, newUoW)
		got := loadSession(t, fx.uow, fx.sess.ID())
		if !reflect.DeepEqual(got.Record(), fx.sess.Record()) {
			t.Errorf("stored record differs:\n got %+v\nwant %+v", got.Record(), fx.sess.Record())
		}
	})

	t.Run("methods list survives storage", func(t *testing.T) {
		uow, f := newUoW(t), NewFactory(t, contractNow)
		user := seedUser(t, uow, f, "")
		sess := f.Session(SessionSpec{User: user, AMR: []string{"otp", "passkey"}})
		mustDo(t, uow, func(ctx context.Context, s port.Stores) error { return s.Sessions.Create(ctx, sess) })
		if got := loadSession(t, uow, sess.ID()); !reflect.DeepEqual(got.AMR(), []string{"otp", "passkey"}) {
			t.Errorf("AMR = %v", got.AMR())
		}
	})

	t.Run("missing and duplicate", func(t *testing.T) {
		fx := newSessionFixture(t, newUoW)
		absent := fx.f.Session(SessionSpec{User: fx.user})
		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			if _, err := s.Sessions.GetForUpdate(ctx, absent.ID()); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("GetForUpdate = %v, want ErrNotFound", err)
			}
			if err := s.Sessions.Save(ctx, absent); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("Save = %v, want ErrNotFound", err)
			}
			return nil
		})
		if err := do(t, fx.uow, func(ctx context.Context, s port.Stores) error { return s.Sessions.Create(ctx, fx.sess) }); err == nil {
			t.Error("Create accepted a duplicate id")
		}
	})

	t.Run("saved changes persist and rollback discards them", func(t *testing.T) {
		fx := newSessionFixture(t, newUoW)
		touch := func(at time.Time, fail bool) {
			_ = do(t, fx.uow, func(ctx context.Context, s port.Stores) error {
				sess, err := s.Sessions.GetForUpdate(ctx, fx.sess.ID())
				if err != nil {
					return err
				}
				if err := sess.Touch(at, session.DefaultPolicy()); err != nil {
					return err
				}
				if err := s.Sessions.Save(ctx, sess); err != nil {
					return err
				}
				if fail {
					return errContractRollback
				}
				return nil
			})
		}
		later := contractNow.Add(24 * time.Hour)
		touch(later, true)
		if got := loadSession(t, fx.uow, fx.sess.ID()); !got.LastActiveAt().Equal(contractNow) {
			t.Errorf("LastActiveAt = %v after a rolled back Save", got.LastActiveAt())
		}
		touch(later, false)
		if got := loadSession(t, fx.uow, fx.sess.ID()); !got.LastActiveAt().Equal(later) {
			t.Errorf("LastActiveAt = %v after a committed Save", got.LastActiveAt())
		}
	})

	t.Run("a save from a stale copy cannot undo a revocation", func(t *testing.T) {
		fx := newSessionFixture(t, newUoW)
		stale := loadSession(t, fx.uow, fx.sess.ID())

		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			live, err := s.Sessions.GetForUpdate(ctx, fx.sess.ID())
			if err != nil {
				return err
			}
			live.Revoke(contractNow.Add(time.Hour))
			return s.Sessions.Save(ctx, live)
		})
		if err := stale.Touch(contractNow.Add(2*time.Hour), session.DefaultPolicy()); err != nil {
			t.Fatal(err)
		}
		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error { return s.Sessions.Save(ctx, stale) })

		got := loadSession(t, fx.uow, fx.sess.ID())
		if !got.RevokedAt().Equal(contractNow.Add(time.Hour)) {
			t.Errorf("RevokedAt = %v: a stale save un-revoked the session", got.RevokedAt())
		}
	})

	t.Run("revoking the others keeps one session and touches nobody else's", func(t *testing.T) {
		fx := newSessionFixture(t, newUoW)
		second, _ := seedSession(t, fx.uow, fx.f, fx.user)
		third, _ := seedSession(t, fx.uow, fx.f, fx.user)
		other := seedUser(t, fx.uow, fx.f, "")
		foreign, _ := seedSession(t, fx.uow, fx.f, other)

		earlier := contractNow.Add(time.Hour)
		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			sess, err := s.Sessions.GetForUpdate(ctx, third.ID())
			if err != nil {
				return err
			}
			sess.Revoke(earlier)
			return s.Sessions.Save(ctx, sess)
		})
		at := contractNow.Add(2 * time.Hour)
		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			return s.Sessions.RevokeOthersForUser(ctx, fx.user.ID(), fx.sess.ID(), at)
		})
		if got := loadSession(t, fx.uow, fx.sess.ID()); !got.RevokedAt().IsZero() {
			t.Errorf("the kept session was revoked at %v", got.RevokedAt())
		}
		if got := loadSession(t, fx.uow, second.ID()); !got.RevokedAt().Equal(at) {
			t.Errorf("another session of the user: RevokedAt = %v, want %v", got.RevokedAt(), at)
		}
		if got := loadSession(t, fx.uow, third.ID()); !got.RevokedAt().Equal(earlier) {
			t.Errorf("an already revoked session: RevokedAt = %v, want the first time %v", got.RevokedAt(), earlier)
		}
		if got := loadSession(t, fx.uow, foreign.ID()); !got.RevokedAt().IsZero() {
			t.Error("another user's session was revoked")
		}
	})

	t.Run("revoke all affects only the user's sessions and keeps earlier times", func(t *testing.T) {
		fx := newSessionFixture(t, newUoW)
		second, _ := seedSession(t, fx.uow, fx.f, fx.user)
		other := seedUser(t, fx.uow, fx.f, "")
		foreign, _ := seedSession(t, fx.uow, fx.f, other)

		earlier := contractNow.Add(time.Hour)
		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			sess, err := s.Sessions.GetForUpdate(ctx, second.ID())
			if err != nil {
				return err
			}
			sess.Revoke(earlier)
			return s.Sessions.Save(ctx, sess)
		})

		at := contractNow.Add(2 * time.Hour)
		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			return s.Sessions.RevokeAllForUser(ctx, fx.user.ID(), at)
		})
		if got := loadSession(t, fx.uow, fx.sess.ID()); !got.RevokedAt().Equal(at) {
			t.Errorf("first session RevokedAt = %v", got.RevokedAt())
		}
		if got := loadSession(t, fx.uow, second.ID()); !got.RevokedAt().Equal(earlier) {
			t.Errorf("already revoked session RevokedAt = %v, want the first time %v", got.RevokedAt(), earlier)
		}
		if got := loadSession(t, fx.uow, foreign.ID()); !got.RevokedAt().IsZero() {
			t.Error("another user's session was revoked")
		}
	})
}

func tokenContract(t *testing.T, newUoW NewUnitOfWork) {
	childOf := func(fx sessionFixture, parent *token.RefreshToken, at time.Time) (*token.RefreshToken, string) {
		secret := fx.f.RefreshSecret()
		id, err := fx.f.IDs.NewRefreshTokenID()
		if err != nil {
			t.Fatal(err)
		}
		child, err := parent.Rotate(at, id, TokenHash(secret), fx.sess.RefreshExpiry(at, session.DefaultPolicy()))
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		return child, secret
	}
	create := func(fx sessionFixture, tok *token.RefreshToken) error {
		return do(t, fx.uow, func(ctx context.Context, s port.Stores) error { return s.Tokens.Create(ctx, tok) })
	}

	t.Run("token is found by hash and by id", func(t *testing.T) {
		fx := newSessionFixture(t, newUoW)
		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			byHash, err := s.Tokens.FindByHash(ctx, fx.root.Hash())
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(byHash.Record(), fx.root.Record()) {
				t.Errorf("FindByHash differs:\n got %+v\nwant %+v", byHash.Record(), fx.root.Record())
			}
			if _, err := s.Tokens.FindByHash(ctx, TokenHash(fx.f.RefreshSecret())); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("FindByHash of an unknown secret = %v, want ErrNotFound", err)
			}
			return nil
		})
		if got := loadToken(t, fx.uow, fx.root.ID()); !reflect.DeepEqual(got.Record(), fx.root.Record()) {
			t.Error("GetForUpdate differs from the stored record")
		}
	})

	t.Run("missing token", func(t *testing.T) {
		fx := newSessionFixture(t, newUoW)
		absent, _ := fx.f.RefreshToken(RefreshSpec{Session: fx.sess})
		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			if _, err := s.Tokens.GetForUpdate(ctx, absent.ID()); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("GetForUpdate = %v, want ErrNotFound", err)
			}
			if err := s.Tokens.Save(ctx, absent); !errors.Is(err, port.ErrNotFound) {
				t.Errorf("Save = %v, want ErrNotFound", err)
			}
			return nil
		})
	})

	t.Run("secret hashes are unique", func(t *testing.T) {
		fx := newSessionFixture(t, newUoW)
		id, _ := fx.f.IDs.NewRefreshTokenID()
		family, _ := fx.f.IDs.NewFamilyID()
		clone, err := token.NewRoot(id, fx.sess.ID(), family, fx.root.Hash(), contractNow, contractNow.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if err := create(fx, clone); !errors.Is(err, port.ErrTokenConflict) {
			t.Errorf("Create with a duplicate hash = %v, want ErrTokenConflict", err)
		}
	})

	t.Run("a parent has one live child", func(t *testing.T) {
		fx := newSessionFixture(t, newUoW)
		parent := loadToken(t, fx.uow, fx.root.ID())
		first, _ := childOf(fx, parent, contractNow.Add(time.Minute))
		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			if err := s.Tokens.Save(ctx, parent); err != nil {
				return err
			}
			return s.Tokens.Create(ctx, first)
		})

		// A second child of the same parent is refused, even built from a fresh copy.
		// The domain would not rotate a used parent, so build the sibling from a record.
		sibling := forgedChild(t, fx, parent, contractNow.Add(2*time.Minute))
		if err := create(fx, sibling); !errors.Is(err, port.ErrTokenConflict) {
			t.Fatalf("second live child = %v, want ErrTokenConflict", err)
		}

		// Once the first child is revoked the slot is free again.
		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			c, err := s.Tokens.GetForUpdate(ctx, first.ID())
			if err != nil {
				return err
			}
			c.Revoke(contractNow.Add(3 * time.Minute))
			return s.Tokens.Save(ctx, c)
		})
		if err := create(fx, sibling); err != nil {
			t.Errorf("child after revoking the previous one: %v", err)
		}
	})

	t.Run("concurrent children of one parent: exactly one wins", func(t *testing.T) {
		fx := newSessionFixture(t, newUoW)
		const workers = 8
		children := make([]*token.RefreshToken, workers)
		for i := range children {
			children[i], _ = childOf(fx, fx.rootCopy(t), contractNow.Add(time.Minute))
		}
		errs := make([]error, workers)
		var wg sync.WaitGroup
		for i := range children {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = fx.uow.Do(context.Background(), func(ctx context.Context, s port.Stores) error {
					return s.Tokens.Create(ctx, children[i])
				})
			}()
		}
		wg.Wait()

		won := 0
		for i, err := range errs {
			switch {
			case err == nil:
				won++
			case !errors.Is(err, port.ErrTokenConflict):
				t.Errorf("worker %d: %v, want nil or ErrTokenConflict", i, err)
			}
		}
		if won != 1 {
			t.Errorf("%d children were stored, want exactly 1", won)
		}
	})

	t.Run("saved changes persist and rollback discards them", func(t *testing.T) {
		fx := newSessionFixture(t, newUoW)
		use := func(fail bool) {
			_ = do(t, fx.uow, func(ctx context.Context, s port.Stores) error {
				tok, err := s.Tokens.GetForUpdate(ctx, fx.root.ID())
				if err != nil {
					return err
				}
				tok.Revoke(contractNow.Add(time.Hour))
				if err := s.Tokens.Save(ctx, tok); err != nil {
					return err
				}
				if fail {
					return errContractRollback
				}
				return nil
			})
		}
		use(true)
		if !loadToken(t, fx.uow, fx.root.ID()).RevokedAt().IsZero() {
			t.Error("a rolled back Save was visible")
		}
		use(false)
		if loadToken(t, fx.uow, fx.root.ID()).RevokedAt().IsZero() {
			t.Error("a committed Save was lost")
		}
	})

	t.Run("a save from a stale copy cannot undo a revocation or a use", func(t *testing.T) {
		fx := newSessionFixture(t, newUoW)
		stale := fx.rootCopy(t)

		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			live, err := s.Tokens.GetForUpdate(ctx, fx.root.ID())
			if err != nil {
				return err
			}
			live.Revoke(contractNow.Add(time.Hour))
			if _, err := live.Rotate(contractNow, mustTokenID(t, fx), TokenHash(fx.f.RefreshSecret()), contractNow.Add(time.Hour)); err == nil {
				t.Error("a revoked token rotated")
			}
			return s.Tokens.Save(ctx, live)
		})
		// The stale copy was never revoked; saving it must not clear the mark.
		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error { return s.Tokens.Save(ctx, stale) })
		if got := loadToken(t, fx.uow, fx.root.ID()); !got.RevokedAt().Equal(contractNow.Add(time.Hour)) {
			t.Errorf("RevokedAt = %v: a stale save un-revoked the token", got.RevokedAt())
		}
	})

	t.Run("revoking the tokens of the other sessions", func(t *testing.T) {
		fx := newSessionFixture(t, newUoW)
		_, secondRoot := seedSession(t, fx.uow, fx.f, fx.user)
		other := seedUser(t, fx.uow, fx.f, "")
		_, foreignRoot := seedSession(t, fx.uow, fx.f, other)

		at := contractNow.Add(time.Hour)
		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			return s.Tokens.RevokeOthersForUser(ctx, fx.user.ID(), fx.sess.ID(), at)
		})
		if !loadToken(t, fx.uow, fx.root.ID()).RevokedAt().IsZero() {
			t.Error("the token of the kept session was revoked")
		}
		if got := loadToken(t, fx.uow, secondRoot.ID()).RevokedAt(); !got.Equal(at) {
			t.Errorf("the token of another session of the user: RevokedAt = %v", got)
		}
		if !loadToken(t, fx.uow, foreignRoot.ID()).RevokedAt().IsZero() {
			t.Error("another user's token was revoked")
		}
	})

	t.Run("revoking by session and by user", func(t *testing.T) {
		fx := newSessionFixture(t, newUoW)
		secondSess, secondRoot := seedSession(t, fx.uow, fx.f, fx.user)
		other := seedUser(t, fx.uow, fx.f, "")
		_, foreignRoot := seedSession(t, fx.uow, fx.f, other)

		at := contractNow.Add(time.Hour)
		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			return s.Tokens.RevokeBySession(ctx, fx.sess.ID(), at)
		})
		if loadToken(t, fx.uow, fx.root.ID()).RevokedAt().IsZero() {
			t.Error("RevokeBySession missed the session's token")
		}
		if !loadToken(t, fx.uow, secondRoot.ID()).RevokedAt().IsZero() {
			t.Error("RevokeBySession touched another session")
		}
		_ = secondSess

		later := contractNow.Add(2 * time.Hour)
		mustDo(t, fx.uow, func(ctx context.Context, s port.Stores) error {
			return s.Tokens.RevokeAllForUser(ctx, fx.user.ID(), later)
		})
		if got := loadToken(t, fx.uow, fx.root.ID()).RevokedAt(); !got.Equal(at) {
			t.Errorf("RevokeAllForUser rewrote an earlier revocation: %v", got)
		}
		if loadToken(t, fx.uow, secondRoot.ID()).RevokedAt().IsZero() {
			t.Error("RevokeAllForUser missed another session of the user")
		}
		if !loadToken(t, fx.uow, foreignRoot.ID()).RevokedAt().IsZero() {
			t.Error("RevokeAllForUser touched another user's token")
		}
	})
}

// rootCopy loads a fresh copy of the root token, as a concurrent request would.
func (fx sessionFixture) rootCopy(t *testing.T) *token.RefreshToken {
	t.Helper()
	return loadToken(t, fx.uow, fx.root.ID())
}

// forgedChild builds a child of parent without going through Rotate, to probe the
// storage invariant that guards against a second live child.
func forgedChild(t *testing.T, fx sessionFixture, parent *token.RefreshToken, at time.Time) *token.RefreshToken {
	t.Helper()
	id, err := fx.f.IDs.NewRefreshTokenID()
	if err != nil {
		t.Fatal(err)
	}
	child, err := token.Restore(token.Record{
		ID: id, SessionID: parent.SessionID(), FamilyID: parent.FamilyID(), ParentID: parent.ID(),
		Hash: TokenHash(fx.f.RefreshSecret()), CreatedAt: at, ExpiresAt: at.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return child
}

func mustTokenID(t *testing.T, fx sessionFixture) token.ID {
	t.Helper()
	id, err := fx.f.IDs.NewRefreshTokenID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}
