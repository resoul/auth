//go:build integration

package pgstore_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"airlance.org/auth/examples/bff"
	"airlance.org/auth/examples/bff/pgstore"
)

var t0 = time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// newPool opens a pool whose tables live in a schema of their own, dropped with the test.
func newPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AIRLANCE_AUTH_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("AIRLANCE_AUTH_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := fmt.Sprintf("bff_test_%d_%d", time.Now().UnixNano(), os.Getpid())
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.MaxConns = 16
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(ctx, `DROP SCHEMA `+schema+` CASCADE`)
		admin.Close()
	})
	if err := pgstore.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return pool
}

func newStore(t *testing.T) (*pgstore.Store, *clock) {
	t.Helper()
	c := &clock{t: t0}
	return pgstore.New(newPool(t), c.Now), c
}

func session(key, sid string, started time.Time) bff.Session {
	return bff.Session{
		Key: key, UserID: "u1", Issuer: "https://auth.example.test", Subject: "sub-1", ProviderSession: sid, IDTokenSealed: "id-sealed",
		RefreshSealed: "refresh-1", Access: map[string]bff.SealedAccess{"https://api.example.test/": {Sealed: "access-1", ExpiresAt: t0.Add(5 * time.Minute)}},
		CreatedAt: t0, SignInStarted: started, ExpiresAt: t0.Add(8 * time.Hour),
	}
}

const iss = "https://auth.example.test"

func TestAMigrationMayRunAtEveryStart(t *testing.T) {
	pool := newPool(t)
	if err := pgstore.Migrate(context.Background(), pool); err != nil {
		t.Fatalf("a second migration = %v", err)
	}
}

func TestALoginIsUsedOnceEvenByTwoRequestsAtTheSameMoment(t *testing.T) {
	s, c := newStore(t)
	ctx := context.Background()
	tx := bff.LoginTx{Key: "k1", State: "st", Nonce: "n", Verifier: "v", ReturnTo: "/home", StartedAt: t0, ExpiresAt: t0.Add(10 * time.Minute)}
	if err := s.PutLogin(ctx, tx); err != nil {
		t.Fatal(err)
	}
	var won atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got, ok, err := s.TakeLogin(ctx, "k1", c.Now()); err != nil {
				t.Error(err)
			} else if ok {
				won.Add(1)
				if got.State != "st" || got.ReturnTo != "/home" || !got.StartedAt.Equal(t0) {
					t.Errorf("login = %+v", got)
				}
			}
		}()
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Errorf("%d requests took the same login", won.Load())
	}
	// An expired one is not given, and is gone either way.
	must(t, s.PutLogin(ctx, bff.LoginTx{Key: "k2", ExpiresAt: t0.Add(time.Minute)}))
	c.Advance(time.Minute)
	if _, ok, err := s.TakeLogin(ctx, "k2", c.Now()); ok || err != nil {
		t.Errorf("an expired login = %v, %v", ok, err)
	}
}

func TestAPersonIsTheirIssuerAndSubjectNotAnEmail(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	var ids sync.Map
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := s.UpsertUser(ctx, iss, "sub-1")
			if err != nil {
				t.Error(err)
			}
			ids.Store(id, true)
		}()
	}
	wg.Wait()
	n := 0
	ids.Range(func(_, _ any) bool { n++; return true })
	if n != 1 {
		t.Errorf("one person got %d identifiers", n)
	}
	a, _ := s.UpsertUser(ctx, iss, "sub-2")
	b, _ := s.UpsertUser(ctx, "https://other.example.test", "sub-1")
	if a == b || a == "" {
		t.Errorf("different people share an id: %q %q", a, b)
	}
}

func TestASessionIsStoredReadAndDeletedWithEverythingOnIt(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	want := session("hash-1", "sid-1", t0)
	must(t, s.CreateSession(ctx, want))
	got, err := s.GetSession(ctx, "hash-1")
	must(t, err)
	if got.UserID != want.UserID || got.Issuer != iss || got.ProviderSession != "sid-1" || got.IDTokenSealed != "id-sealed" || got.RefreshSealed != "refresh-1" ||
		!got.CreatedAt.Equal(t0) || !got.SignInStarted.Equal(t0) || !got.ExpiresAt.Equal(want.ExpiresAt) ||
		got.Access["https://api.example.test/"].Sealed != "access-1" || !got.Access["https://api.example.test/"].ExpiresAt.Equal(t0.Add(5*time.Minute)) {
		t.Errorf("session = %+v", got)
	}
	if _, err := s.GetSession(ctx, "nothing"); !errors.Is(err, bff.ErrNoSession) {
		t.Errorf("a missing session = %v", err)
	}
	must(t, s.DeleteSession(ctx, "hash-1"))
	must(t, s.DeleteSession(ctx, "hash-1"))
	if _, err := s.GetSession(ctx, "hash-1"); !errors.Is(err, bff.ErrNoSession) {
		t.Errorf("a deleted session = %v", err)
	}
}

func TestTwoRefreshesNeverRunAtOnceAndTheSecondSeesTheFirstsToken(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	must(t, s.CreateSession(ctx, session("hash-1", "sid-1", t0)))

	var inside, overlap, runs atomic.Int32
	var wg sync.WaitGroup
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.WithSessionLock(ctx, "hash-1", func(sess *bff.Session) error {
				if inside.Add(1) > 1 {
					overlap.Add(1)
				}
				defer inside.Add(-1)
				time.Sleep(20 * time.Millisecond)
				// What a refresh does: present the token the session holds, and keep the one that comes back.
				runs.Add(1)
				sess.RefreshSealed = fmt.Sprintf("%s+", sess.RefreshSealed)
				return nil
			})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	got, _ := s.GetSession(ctx, "hash-1")
	if overlap.Load() != 0 {
		t.Errorf("%d functions ran inside the lock together", overlap.Load())
	}
	if got.RefreshSealed != "refresh-1++++++" || runs.Load() != 6 {
		t.Errorf("each run should have seen the one before it: %q after %d runs", got.RefreshSealed, runs.Load())
	}

	// A function that fails changes nothing; a session that is not there is ErrNoSession.
	boom := errors.New("boom")
	if err := s.WithSessionLock(ctx, "hash-1", func(sess *bff.Session) error { sess.RefreshSealed = "lost"; return boom }); !errors.Is(err, boom) {
		t.Errorf("err = %v", err)
	}
	if got, _ := s.GetSession(ctx, "hash-1"); got.RefreshSealed != "refresh-1++++++" {
		t.Errorf("a failed function stored %q", got.RefreshSealed)
	}
	if err := s.WithSessionLock(ctx, "nothing", func(*bff.Session) error { return nil }); !errors.Is(err, bff.ErrNoSession) {
		t.Errorf("a missing session = %v", err)
	}
}

func TestALogoutNoticeEndsTheSessionsOnceAndAFailedOneChangesNothing(t *testing.T) {
	s, c := newStore(t)
	ctx := context.Background()
	must(t, s.CreateSession(ctx, session("hash-1", "sid-1", t0)))
	must(t, s.CreateSession(ctx, session("hash-2", "sid-1", t0)))
	must(t, s.CreateSession(ctx, session("hash-3", "sid-2", t0)))

	c.Advance(time.Second)
	first, n, err := s.EndProviderSession(ctx, iss, "sid-1", "jti-1", c.Now().Add(time.Minute))
	if err != nil || !first || n != 2 {
		t.Fatalf("first = %v, ended = %d, %v", first, n, err)
	}
	if _, err := s.GetSession(ctx, "hash-3"); err != nil {
		t.Errorf("another sign-in's session was ended: %v", err)
	}
	// The same notice again: answered, not applied.
	if first, n, err := s.EndProviderSession(ctx, iss, "sid-1", "jti-1", c.Now().Add(time.Minute)); err != nil || first || n != 0 {
		t.Errorf("a repeat = %v, %d, %v", first, n, err)
	}
	// A sign-in that began before the notice cannot become a session; one that began after it can.
	if err := s.CreateSession(ctx, session("hash-4", "sid-1", t0)); !errors.Is(err, bff.ErrSessionEnded) {
		t.Errorf("a sign-in begun before the notice = %v", err)
	}
	must(t, s.CreateSession(ctx, session("hash-5", "sid-1", c.Now().Add(time.Millisecond))))

	// The same jti two hours later, redelivered with a re-signed token: still remembered, so the new sign-in is left alone.
	c.Advance(2 * time.Hour)
	if first, _, err := s.EndProviderSession(ctx, iss, "sid-1", "jti-1", c.Now().Add(-time.Hour)); err != nil || first {
		t.Errorf("a late repeat = %v, %v", first, err)
	}
	if _, err := s.GetSession(ctx, "hash-5"); err != nil {
		t.Errorf("a late repeat ended a later sign-in: %v", err)
	}
	// The same jti under another issuer is another notice.
	if first, _, _ := s.EndProviderSession(ctx, "https://other.example.test", "sid-1", "jti-1", c.Now().Add(time.Minute)); !first {
		t.Error("a jti of another issuer was taken for a repeat")
	}
}

func TestANoticeAndASessionBeingCreatedAreOrdered(t *testing.T) {
	// However the two interleave, a sign-in that began before the notice does not survive it.
	for range 20 {
		s, c := newStore(t)
		ctx := context.Background()
		start := c.Now()
		c.Advance(time.Millisecond)
		var wg sync.WaitGroup
		var created error
		wg.Add(2)
		go func() { defer wg.Done(); created = s.CreateSession(ctx, session("hash-1", "sid-1", start)) }()
		go func() {
			defer wg.Done()
			if _, _, err := s.EndProviderSession(ctx, iss, "sid-1", "jti-1", c.Now().Add(time.Minute)); err != nil {
				t.Error(err)
			}
		}()
		wg.Wait()
		if created != nil && !errors.Is(created, bff.ErrSessionEnded) {
			t.Fatal(created)
		}
		if _, err := s.GetSession(ctx, "hash-1"); err == nil {
			t.Fatal("a session of a sign-in that the notice ended is still there")
		}
	}
}

func TestANoticeDuringARefreshEndsTheSessionAndTheRefreshDoesNotBringItBack(t *testing.T) {
	s, c := newStore(t)
	ctx := context.Background()
	must(t, s.CreateSession(ctx, session("hash-1", "sid-1", t0)))
	started, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- s.WithSessionLock(ctx, "hash-1", func(sess *bff.Session) error {
			close(started)
			<-release
			sess.RefreshSealed = "rotated"
			return nil
		})
	}()
	<-started
	c.Advance(time.Second)
	// The notice does not wait for the provider call: the lock is not a row lock.
	if _, n, err := s.EndProviderSession(ctx, iss, "sid-1", "jti-1", c.Now().Add(time.Minute)); err != nil || n != 1 {
		t.Fatalf("the notice ended %d sessions, %v", n, err)
	}
	close(release)
	must(t, <-done)
	if _, err := s.GetSession(ctx, "hash-1"); !errors.Is(err, bff.ErrNoSession) {
		t.Errorf("the refresh brought back a session the notice ended: %v", err)
	}
}

func TestWhatARefreshLeavesIsStoredEvenIfTheRequestIsCancelled(t *testing.T) {
	s, _ := newStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	must(t, s.CreateSession(context.Background(), session("hash-1", "sid-1", t0)))
	err := s.WithSessionLock(ctx, "hash-1", func(sess *bff.Session) error {
		must(t, sess.BeginRefresh(ctx))
		// The provider rotated the token, and the request goes away before the result is kept.
		sess.RefreshSealed = "rotated"
		cancel()
		return nil
	})
	if err != nil {
		t.Fatalf("WithSessionLock = %v", err)
	}
	got, err := s.GetSession(context.Background(), "hash-1")
	must(t, err)
	if got.RefreshSealed != "rotated" || got.RefreshInterrupted {
		t.Errorf("after a cancelled request: refresh %q, interrupted %v", got.RefreshSealed, got.RefreshInterrupted)
	}
}

func TestARefreshThatNeverFinishedIsReportedToTheNextCaller(t *testing.T) {
	pool := newPool(t)
	s := pgstore.New(pool, (&clock{t: t0}).Now)
	ctx := context.Background()
	must(t, s.CreateSession(ctx, session("hash-1", "sid-1", t0)))
	// A process that marked the refresh and died: the mark is in the row, and nothing else happens to it.
	must(t, s.WithSessionLock(ctx, "hash-1", func(sess *bff.Session) error {
		if sess.RefreshInterrupted || sess.BeginRefresh == nil {
			t.Errorf("a fresh session: interrupted %v, hook %v", sess.RefreshInterrupted, sess.BeginRefresh != nil)
		}
		return nil
	}))
	_, err := pool.Exec(ctx, `UPDATE bff_sessions SET refresh_started_at = $1 WHERE key = 'hash-1'`, t0)
	must(t, err)
	if got, _ := s.GetSession(ctx, "hash-1"); !got.RefreshInterrupted {
		t.Error("a mark is not read back")
	}
	var seen bool
	must(t, s.WithSessionLock(ctx, "hash-1", func(sess *bff.Session) error { seen = sess.RefreshInterrupted; return nil }))
	if !seen {
		t.Error("the next caller was not told")
	}
	if got, _ := s.GetSession(ctx, "hash-1"); got.RefreshInterrupted {
		t.Error("the mark outlived the call that handled it")
	}
	// A function that marks and then fails clears the mark too, and a missing session cannot be marked.
	_ = s.WithSessionLock(ctx, "hash-1", func(sess *bff.Session) error {
		must(t, sess.BeginRefresh(ctx))
		return errors.New("refused")
	})
	if got, _ := s.GetSession(ctx, "hash-1"); got.RefreshInterrupted {
		t.Error("a failed function left the mark")
	}
	must(t, s.DeleteSession(ctx, "hash-1"))
	if err := s.WithSessionLock(ctx, "hash-1", func(*bff.Session) error { return nil }); !errors.Is(err, bff.ErrNoSession) {
		t.Errorf("a missing session = %v", err)
	}
}

func TestRefreshesCannotStarveThemselvesOfConnections(t *testing.T) {
	dsn := os.Getenv("AIRLANCE_AUTH_TEST_DATABASE_URL")
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	must(t, err)
	schema := fmt.Sprintf("bff_pool_%d_%d", time.Now().UnixNano(), os.Getpid())
	_, err = admin.Exec(ctx, `CREATE SCHEMA `+schema)
	must(t, err)
	cfg, err := pgxpool.ParseConfig(dsn)
	must(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	must(t, err)
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(ctx, `DROP SCHEMA `+schema+` CASCADE`)
		admin.Close()
	})
	must(t, pgstore.Migrate(ctx, pool))
	s := pgstore.New(pool, (&clock{t: t0}).Now)
	must(t, s.CreateSession(ctx, session("hash-1", "sid-1", t0)))
	must(t, s.CreateSession(ctx, session("hash-2", "sid-2", t0)))

	// As many refreshes as the pool has connections, each marking its refresh: the mark must not ask for another connection.
	timeout, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for _, key := range []string{"hash-1", "hash-2"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.WithSessionLock(timeout, key, func(sess *bff.Session) error {
				if err := sess.BeginRefresh(timeout); err != nil {
					return err
				}
				time.Sleep(200 * time.Millisecond)
				sess.RefreshSealed = "rotated-" + key
				return nil
			})
			if err != nil {
				t.Errorf("%s: %v", key, err)
			}
		}()
	}
	wg.Wait()
	if got, _ := s.GetSession(ctx, "hash-2"); got.RefreshSealed != "rotated-hash-2" || got.RefreshInterrupted {
		t.Errorf("session = %+v", got)
	}
}

func TestSeveralInstancesMayMigrateAtTheSameMoment(t *testing.T) {
	dsn := os.Getenv("AIRLANCE_AUTH_TEST_DATABASE_URL")
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	must(t, err)
	schema := fmt.Sprintf("bff_mig_%d_%d", time.Now().UnixNano(), os.Getpid())
	_, err = admin.Exec(ctx, `CREATE SCHEMA `+schema)
	must(t, err)
	cfg, err := pgxpool.ParseConfig(dsn)
	must(t, err)
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.MaxConns = 16
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	must(t, err)
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(ctx, `DROP SCHEMA `+schema+` CASCADE`)
		admin.Close()
	})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := pgstore.Migrate(ctx, pool); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}

func TestOldRowsAreRemovedAsTheStoreIsUsed(t *testing.T) {
	s, c := newStore(t)
	ctx := context.Background()
	must(t, s.CreateSession(ctx, session("hash-1", "sid-1", t0)))
	c.Advance(9 * time.Hour) // past the session's end
	must(t, s.PutLogin(ctx, bff.LoginTx{Key: "k", ExpiresAt: c.Now().Add(time.Minute)}))
	if _, err := s.GetSession(ctx, "hash-1"); !errors.Is(err, bff.ErrNoSession) {
		t.Errorf("an expired session was kept: %v", err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
