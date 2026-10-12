//go:build integration

package postgres_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"airlance.org/auth/internal/adapter/crypto"
	"airlance.org/auth/internal/adapter/id"
	"airlance.org/auth/internal/adapter/jwt"
	"airlance.org/auth/internal/adapter/metrics"
	"airlance.org/auth/internal/adapter/postgres"
	"airlance.org/auth/internal/application/port"
	appsession "airlance.org/auth/internal/application/session"
	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/domain/session"
	"airlance.org/auth/internal/domain/token"
	"airlance.org/auth/internal/testutil"
)

const (
	sess1   = "018f3b2a-1c4d-7a5e-8b6f-9c0d1e2f3a01"
	sess2   = "018f3b2a-1c4d-7a5e-8b6f-9c0d1e2f3a02"
	tok1    = "018f3b2a-1c4d-7a5e-8b6f-9c0d1e2f3b01"
	tok2    = "018f3b2a-1c4d-7a5e-8b6f-9c0d1e2f3b02"
	tok3    = "018f3b2a-1c4d-7a5e-8b6f-9c0d1e2f3b03"
	family1 = "018f3b2a-1c4d-7a5e-8b6f-9c0d1e2f3c01"
)

func insertSession(t *testing.T, db *sql.DB, id, user string) {
	t.Helper()
	exec(t, db, `INSERT INTO sessions (id, user_id, binding_hash, amr, auth_time, device_name, created_at, last_active_at, idle_expires_at, expires_at)
		VALUES ($1, $2, `+binding+`, ARRAY['otp'], now(), 'laptop', now(), now(), now() + interval '30 days', now() + interval '90 days')`, id, user)
}

func insertToken(t *testing.T, db *sql.DB, id, session, parent, hashSeed string) {
	t.Helper()
	var p any
	if parent != "" {
		p = parent
	}
	exec(t, db, `INSERT INTO refresh_tokens (id, session_id, family_id, parent_id, token_hash, created_at, expires_at)
		VALUES ($1, $2, $3, $4, decode(repeat($5, 32), 'hex'), now(), now() + interval '30 days')`, id, session, family1, p, hashSeed)
}

func TestSessionConstraints(t *testing.T) {
	db := migratedDB(t)
	insertUser(t, db, userID, "alice@example.test")
	insertSession(t, db, sess1, userID)

	insert := func(binding, amr, device, createdAt, lastActive, idleExp, exp, authTime string) (string, []any) {
		return `INSERT INTO sessions (id, user_id, binding_hash, amr, auth_time, device_name, created_at, last_active_at, idle_expires_at, expires_at)
			VALUES ($1, $2, ` + binding + `, ` + amr + `, ` + authTime + `, $3, ` + createdAt + `, ` + lastActive + `, ` + idleExp + `, ` + exp + `)`, []any{sess2, userID, device}
	}
	now := `now()`
	tests := []struct {
		name       string
		constraint string
		binding    string
		amr        string
		device     string
		created    string
		lastActive string
		idle       string
		expires    string
		authTime   string
	}{
		{"duplicate id", "sessions_pkey", binding, "ARRAY['otp']", "d", now, now, now + ` + interval '1 day'`, now + ` + interval '2 days'`, now},
		{"binding length", "sessions_binding_length", `decode('abab', 'hex')`, "ARRAY['otp']", "d", now, now, now + ` + interval '1 day'`, now + ` + interval '2 days'`, now},
		{"no methods", "sessions_amr", binding, "ARRAY[]::text[]", "d", now, now, now + ` + interval '1 day'`, now + ` + interval '2 days'`, now},
		{"empty method", "sessions_amr", binding, "ARRAY['otp','']", "d", now, now, now + ` + interval '1 day'`, now + ` + interval '2 days'`, now},
		{"long device name", "sessions_device_name", binding, "ARRAY['otp']", string(make([]byte, 0)) + "0123456789012345678901234567890123456789012345678901234567890123456789", now, now, now + ` + interval '1 day'`, now + ` + interval '2 days'`, now},
		{"auth time after creation", "sessions_auth_time", binding, "ARRAY['otp']", "d", now, now, now + ` + interval '1 day'`, now + ` + interval '2 days'`, now + ` + interval '1 hour'`},
		{"activity before creation", "sessions_activity", binding, "ARRAY['otp']", "d", now, now + ` - interval '1 hour'`, now + ` + interval '1 day'`, now + ` + interval '2 days'`, now},
		{"idle past absolute", "sessions_lifetimes", binding, "ARRAY['otp']", "d", now, now, now + ` + interval '3 days'`, now + ` + interval '2 days'`, now},
		{"expiry not after creation", "sessions_lifetimes", binding, "ARRAY['otp']", "d", now, now, now + ` + interval '1 day'`, now, now},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := sess2
			if tt.name == "duplicate id" {
				id = sess1
			}
			query, args := insert(tt.binding, tt.amr, tt.device, tt.created, tt.lastActive, tt.idle, tt.expires, tt.authTime)
			args[0] = id
			mustViolate(t, db, tt.constraint, query, args...)
		})
	}
}

func TestRefreshTokenConstraints(t *testing.T) {
	db := migratedDB(t)
	insertUser(t, db, userID, "alice@example.test")
	insertSession(t, db, sess1, userID)
	insertToken(t, db, tok1, sess1, "", "aa")

	mustViolate(t, db, "refresh_tokens_hash_unique",
		`INSERT INTO refresh_tokens (id, session_id, family_id, token_hash, created_at, expires_at) VALUES ($1, $2, $3, decode(repeat('aa', 32), 'hex'), now(), now() + interval '1 day')`, tok2, sess1, family1)
	mustViolate(t, db, "refresh_tokens_hash_length",
		`INSERT INTO refresh_tokens (id, session_id, family_id, token_hash, created_at, expires_at) VALUES ($1, $2, $3, decode('abab', 'hex'), now(), now() + interval '1 day')`, tok2, sess1, family1)
	mustViolate(t, db, "refresh_tokens_period",
		`INSERT INTO refresh_tokens (id, session_id, family_id, token_hash, created_at, expires_at) VALUES ($1, $2, $3, decode(repeat('bb', 32), 'hex'), now(), now())`, tok2, sess1, family1)
	mustViolate(t, db, "refresh_tokens_not_own_parent",
		`INSERT INTO refresh_tokens (id, session_id, family_id, parent_id, token_hash, created_at, expires_at) VALUES ($1, $2, $3, $1, decode(repeat('bb', 32), 'hex'), now(), now() + interval '1 day')`, tok2, sess1, family1)

	_, err := db.Exec(`INSERT INTO refresh_tokens (id, session_id, family_id, token_hash, created_at, expires_at) VALUES ($1, $2, $3, decode(repeat('cc', 32), 'hex'), now(), now() + interval '1 day')`, tok2, sess2, family1)
	if err == nil {
		t.Error("a token of a missing session was accepted")
	}
}

func TestOnlyOneLiveChildPerParent(t *testing.T) {
	db := migratedDB(t)
	insertUser(t, db, userID, "alice@example.test")
	insertSession(t, db, sess1, userID)
	insertToken(t, db, tok1, sess1, "", "aa")
	insertToken(t, db, tok2, sess1, tok1, "bb")

	childQuery := `INSERT INTO refresh_tokens (id, session_id, family_id, parent_id, token_hash, created_at, expires_at)
		VALUES ($1, $2, $3, $4, decode(repeat('cc', 32), 'hex'), now(), now() + interval '1 day')`
	mustViolate(t, db, "refresh_one_live_child", childQuery, tok3, sess1, family1, tok1)

	// Revoking the first child frees the slot, which keeps history for a replacement policy.
	exec(t, db, `UPDATE refresh_tokens SET revoked_at = now() WHERE id = $1`, tok2)
	exec(t, db, childQuery, tok3, sess1, family1, tok1)
	if count(t, db, "refresh_tokens") != 3 {
		t.Error("the revoked child must stay as history")
	}
	// Roots have no parent, so any number of them may exist.
	insertToken(t, db, "018f3b2a-1c4d-7a5e-8b6f-9c0d1e2f3b09", sess1, "", "dd")
	insertToken(t, db, "018f3b2a-1c4d-7a5e-8b6f-9c0d1e2f3b0a", sess1, "", "ee")
}

func TestSessionDeletionCascades(t *testing.T) {
	db := migratedDB(t)
	insertUser(t, db, userID, "alice@example.test")
	insertSession(t, db, sess1, userID)
	insertSession(t, db, sess2, userID)
	insertToken(t, db, tok1, sess1, "", "aa")
	insertToken(t, db, tok2, sess1, tok1, "bb")
	insertToken(t, db, tok3, sess2, "", "cc")

	t.Run("deleting a session deletes its tokens only", func(t *testing.T) {
		exec(t, db, `DELETE FROM sessions WHERE id = $1`, sess1)
		if count(t, db, "refresh_tokens") != 1 || count(t, db, "sessions") != 1 {
			t.Errorf("sessions=%d tokens=%d", count(t, db, "sessions"), count(t, db, "refresh_tokens"))
		}
	})
	t.Run("deleting a user deletes sessions and tokens", func(t *testing.T) {
		exec(t, db, `DELETE FROM users WHERE id = $1`, userID)
		if count(t, db, "sessions") != 0 || count(t, db, "refresh_tokens") != 0 {
			t.Errorf("sessions=%d tokens=%d", count(t, db, "sessions"), count(t, db, "refresh_tokens"))
		}
	})
}

func TestDeletingAParentTokenDeletesItsDescendants(t *testing.T) {
	db := migratedDB(t)
	insertUser(t, db, userID, "alice@example.test")
	insertSession(t, db, sess1, userID)
	insertToken(t, db, tok1, sess1, "", "aa")
	insertToken(t, db, tok2, sess1, tok1, "bb")
	insertToken(t, db, tok3, sess1, tok2, "cc")

	exec(t, db, `DELETE FROM refresh_tokens WHERE id = $1`, tok1)
	if n := count(t, db, "refresh_tokens"); n != 0 {
		t.Errorf("%d descendants survived the deletion of their ancestor", n)
	}
}

// ---- session use cases on the real database ----

type sessionApp struct {
	t         *testing.T
	store     *postgres.Store
	db        *sql.DB
	faults    *faultyUoW
	clock     *testutil.FakeClock
	issuer    *appsession.Issuer
	refresh   *appsession.Refresh
	revoke    *appsession.RevokeSession
	revokeAll *appsession.RevokeAll
}

func newSessionApp(t *testing.T) *sessionApp {
	t.Helper()
	store, db := newStore(t)
	a := &sessionApp{t: t, store: store, db: db, faults: &faultyUoW{inner: store}, clock: testutil.NewFakeClock(t0)}
	var err error
	secrets := crypto.Refresh{}
	policy := session.DefaultPolicy()
	if a.issuer, err = appsession.NewIssuer(appsession.IssuerDeps{SessionIDs: id.Generator{}, TokenIDs: id.Generator{}, Secrets: secrets, Policy: policy}); err != nil {
		t.Fatal(err)
	}
	keys := testutil.NewSigningKeyPEM(t)
	ring, err := jwt.LoadRing("sign-a", map[string]string{"sign-a": testutil.WriteFile(t, "a.pem", keys.Private)})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jwt.NewSigner(ring, a.clock, "https://auth.example.test", "example", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if a.refresh, err = appsession.NewRefresh(appsession.RefreshDeps{UnitOfWork: a.faults, Clock: a.clock, TokenIDs: id.Generator{}, Secrets: secrets, Signer: signer, Metrics: metrics.New(), Policy: policy}); err != nil {
		t.Fatal(err)
	}
	if a.revoke, err = appsession.NewRevokeSession(appsession.RevokeDeps{UnitOfWork: a.faults, Clock: a.clock}); err != nil {
		t.Fatal(err)
	}
	if a.revokeAll, err = appsession.NewRevokeAll(appsession.RevokeDeps{UnitOfWork: a.faults, Clock: a.clock}); err != nil {
		t.Fatal(err)
	}
	return a
}

func (a *sessionApp) newUser(email string) *identity.User {
	a.t.Helper()
	uid, err := id.Generator{}.NewUserID()
	if err != nil {
		a.t.Fatal(err)
	}
	parsed, err := identity.ParseEmail(email)
	if err != nil {
		a.t.Fatal(err)
	}
	candidate, err := identity.NewUser(uid, parsed, a.clock.Now())
	if err != nil {
		a.t.Fatal(err)
	}
	var user *identity.User
	err = a.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		var err error
		user, _, err = st.Users.Ensure(ctx, candidate)
		return err
	})
	if err != nil {
		a.t.Fatal(err)
	}
	return user
}

func (a *sessionApp) signIn(user *identity.User, device string) appsession.Issued {
	a.t.Helper()
	var issued appsession.Issued
	err := a.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		var err error
		issued, err = a.issuer.Issue(ctx, st, a.clock.Now(), appsession.IssueParams{
			UserID: user.ID(), Binding: testutil.BindingHash(device), AMR: []string{"otp"}, AuthTime: a.clock.Now(), DeviceName: device,
		})
		return err
	})
	if err != nil {
		a.t.Fatalf("sign in: %v", err)
	}
	return issued
}

func (a *sessionApp) exchange(secret string) appsession.RefreshResult {
	a.t.Helper()
	res, err := a.refresh.Execute(context.Background(), appsession.RefreshCommand{RefreshSecret: secret})
	if err != nil {
		a.t.Errorf("refresh: %v", err)
	}
	return res
}

func (a *sessionApp) sessionRevoked(id session.ID) bool {
	a.t.Helper()
	var revoked bool
	if err := a.db.QueryRow(`SELECT revoked_at IS NOT NULL FROM sessions WHERE id = $1`, id.String()).Scan(&revoked); err != nil {
		a.t.Fatal(err)
	}
	return revoked
}

func (a *sessionApp) liveTokens(id session.ID) int {
	a.t.Helper()
	var n int
	if err := a.db.QueryRow(`SELECT count(*) FROM refresh_tokens WHERE session_id = $1 AND revoked_at IS NULL`, id.String()).Scan(&n); err != nil {
		a.t.Fatal(err)
	}
	return n
}

func TestRefreshChainOnPostgres(t *testing.T) {
	a := newSessionApp(t)
	issued := a.signIn(a.newUser("alice@example.test"), "laptop")

	secret := issued.RefreshSecret
	for day := 1; day <= 5; day++ {
		a.clock.Advance(24 * time.Hour)
		res := a.exchange(secret)
		if res.Outcome != appsession.OutcomeOK {
			t.Fatalf("exchange %d = %+v", day, res)
		}
		secret = res.NewRefreshSecret
	}
	var total, used int
	if err := a.db.QueryRow(`SELECT count(*), count(used_at) FROM refresh_tokens WHERE session_id = $1`, issued.Session.ID().String()).Scan(&total, &used); err != nil {
		t.Fatal(err)
	}
	if total != 6 || used != 5 || a.liveTokens(issued.Session.ID()) != 6 {
		t.Errorf("tokens=%d used=%d live=%d, want a chain of 6 with the last unused", total, used, a.liveTokens(issued.Session.ID()))
	}
}

func TestReplayRevocationIsCommittedOnPostgres(t *testing.T) {
	a := newSessionApp(t)
	issued := a.signIn(a.newUser("alice@example.test"), "laptop")
	child := a.exchange(issued.RefreshSecret)

	replay := a.exchange(issued.RefreshSecret)
	if replay.Outcome != appsession.OutcomeDenied || replay.Reason != appsession.ReasonTokenReused {
		t.Fatalf("replay = %+v", replay)
	}
	if !a.sessionRevoked(issued.Session.ID()) || a.liveTokens(issued.Session.ID()) != 0 {
		t.Errorf("revoked=%v live=%d: the revocation must be committed with the denial", a.sessionRevoked(issued.Session.ID()), a.liveTokens(issued.Session.ID()))
	}
	if res := a.exchange(child.NewRefreshSecret); res.Outcome != appsession.OutcomeDenied {
		t.Errorf("the child of a replayed token still works: %+v", res)
	}
}

func TestParallelRefreshOfOneTokenOnPostgres(t *testing.T) {
	a := newSessionApp(t)
	issued := a.signIn(a.newUser("alice@example.test"), "laptop")

	const workers = 16
	results := make([]appsession.RefreshResult, workers)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = a.exchange(issued.RefreshSecret)
		}()
	}
	wg.Wait()

	var winner *appsession.RefreshResult
	for i := range results {
		if results[i].Outcome == appsession.OutcomeOK {
			if winner != nil {
				t.Fatal("two parallel exchanges both succeeded")
			}
			winner = &results[i]
		}
	}
	if winner == nil {
		t.Fatal("no exchange succeeded")
	}
	if !a.sessionRevoked(issued.Session.ID()) || a.liveTokens(issued.Session.ID()) != 0 {
		t.Error("strict policy: parallel use of one token must end the session")
	}
	if res := a.exchange(winner.NewRefreshSecret); res.Outcome != appsession.OutcomeDenied {
		t.Errorf("the winner's child still works: %+v", res)
	}
}

func TestRefreshRacingSignOutLeavesNoLiveToken(t *testing.T) {
	// One subtest per round: each round's store and schema are released when it ends, so 25
	// rounds do not hold 25 connection pools at once.
	for i := 0; i < 25; i++ {
		t.Run(fmt.Sprintf("round %d", i), func(t *testing.T) { raceRefreshAgainstSignOut(t, i) })
	}
}

func raceRefreshAgainstSignOut(t *testing.T, i int) {
	a := newSessionApp(t)
	user := a.newUser("alice@example.test")
	issued := a.signIn(user, "laptop")

	var refreshRes appsession.RefreshResult
	var revokeRes appsession.RevokeResult
	var revokeErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); refreshRes = a.exchange(issued.RefreshSecret) }()
	go func() {
		defer wg.Done()
		revokeRes, revokeErr = a.revoke.Execute(context.Background(), appsession.RevokeSessionCommand{ActorUserID: user.ID(), SessionID: issued.Session.ID().String()})
	}()
	wg.Wait()
	if revokeErr != nil || revokeRes.Outcome != appsession.OutcomeOK {
		t.Fatalf("iteration %d: revoke = %+v, %v", i, revokeRes, revokeErr)
	}

	if !a.sessionRevoked(issued.Session.ID()) {
		t.Fatalf("iteration %d: the session survived sign-out", i)
	}
	if live := a.liveTokens(issued.Session.ID()); live != 0 {
		t.Fatalf("iteration %d: %d live tokens after sign-out (refresh: %+v)", i, live, refreshRes)
	}
	if refreshRes.Outcome == appsession.OutcomeOK {
		if res := a.exchange(refreshRes.NewRefreshSecret); res.Outcome != appsession.OutcomeDenied {
			t.Fatalf("iteration %d: a token issued during sign-out still works: %+v", i, res)
		}
	}
}

func TestMixedRefreshAndRevokeAllNeverFailOrLeakTokens(t *testing.T) {
	a := newSessionApp(t)
	user := a.newUser("alice@example.test")
	const devices = 6
	issued := make([]appsession.Issued, devices)
	for i := range issued {
		issued[i] = a.signIn(user, string(rune('a'+i))+"-device")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for i := range issued {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := a.refresh.Execute(ctx, appsession.RefreshCommand{RefreshSecret: issued[i].RefreshSecret}); err != nil {
				t.Errorf("refresh %d: %v", i, err)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := a.revokeAll.Execute(ctx, appsession.RevokeAllCommand{ActorUserID: user.ID()}); err != nil {
			t.Errorf("revoke all: %v", err)
		}
	}()
	wg.Wait()

	for i := range issued {
		if !a.sessionRevoked(issued[i].Session.ID()) || a.liveTokens(issued[i].Session.ID()) != 0 {
			t.Errorf("device %d survived revoke all (live tokens %d)", i, a.liveTokens(issued[i].Session.ID()))
		}
	}
}

func TestFailedExchangeRollsBackOnPostgres(t *testing.T) {
	a := newSessionApp(t)
	issued := a.signIn(a.newUser("alice@example.test"), "laptop")
	a.faults.wrap = func(s port.Stores) port.Stores { s.Tokens = failingTokenCreate{s.Tokens}; return s }

	_, err := a.refresh.Execute(context.Background(), appsession.RefreshCommand{RefreshSecret: issued.RefreshSecret})
	if !errors.Is(err, errBoom) {
		t.Fatalf("error = %v, want boom", err)
	}
	var used, total int
	if err := a.db.QueryRow(`SELECT count(*), count(used_at) FROM refresh_tokens WHERE session_id = $1`, issued.Session.ID().String()).Scan(&total, &used); err != nil {
		t.Fatal(err)
	}
	if total != 1 || used != 0 {
		t.Errorf("tokens=%d used=%d: the failed exchange must leave the token untouched", total, used)
	}
	a.faults.wrap = nil
	if res := a.exchange(issued.RefreshSecret); res.Outcome != appsession.OutcomeOK {
		t.Errorf("retry = %+v", res)
	}
}

func TestIssueFailureRollsBackUserSessionAndTokens(t *testing.T) {
	a := newSessionApp(t)
	user := a.newUser("alice@example.test")
	err := a.faults.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		st.Tokens = failingTokenCreate{st.Tokens}
		_, err := a.issuer.Issue(ctx, st, a.clock.Now(), appsession.IssueParams{
			UserID: user.ID(), Binding: testutil.BindingHash("x"), AMR: []string{"otp"}, AuthTime: a.clock.Now(),
		})
		return err
	})
	if !errors.Is(err, errBoom) {
		t.Fatalf("error = %v", err)
	}
	if count(t, a.db, "sessions") != 0 || count(t, a.db, "refresh_tokens") != 0 {
		t.Error("a failed issue left rows behind")
	}
}

type failingTokenCreate struct{ port.RefreshTokenRepository }

func (failingTokenCreate) Create(context.Context, *token.RefreshToken) error { return errBoom }

// hookSessions runs a callback right after the session is locked, to interleave
// another request at the exact point where the lock matters.
type hookSessions struct {
	port.SessionRepository
	afterLock func()
}

func (h hookSessions) GetForUpdate(ctx context.Context, id session.ID) (*session.Session, error) {
	s, err := h.SessionRepository.GetForUpdate(ctx, id)
	if err == nil {
		h.afterLock()
	}
	return s, err
}

// A sign-out that arrives while a refresh holds the session lock must wait for it
// and then also revoke the token the refresh just issued. Without the session
// lock the sign-out would commit first and the new token would stay alive.
func TestSignOutWaitsForARefreshInProgress(t *testing.T) {
	a := newSessionApp(t)
	user := a.newUser("alice@example.test")
	issued := a.signIn(user, "laptop")

	direct, err := appsession.NewRevokeSession(appsession.RevokeDeps{UnitOfWork: a.store, Clock: a.clock})
	if err != nil {
		t.Fatal(err)
	}
	signedOut := make(chan appsession.RevokeResult, 1)
	a.faults.wrap = func(s port.Stores) port.Stores {
		s.Sessions = hookSessions{SessionRepository: s.Sessions, afterLock: func() {
			go func() {
				res, err := direct.Execute(context.Background(), appsession.RevokeSessionCommand{ActorUserID: user.ID(), SessionID: issued.Session.ID().String()})
				if err != nil {
					t.Errorf("sign-out: %v", err)
				}
				signedOut <- res
			}()
			// Give the sign-out time to run into the lock (or, without it, to finish).
			time.Sleep(300 * time.Millisecond)
		}}
		return s
	}

	refreshed := a.exchange(issued.RefreshSecret)
	a.faults.wrap = nil
	if refreshed.Outcome != appsession.OutcomeOK {
		t.Fatalf("refresh = %+v", refreshed)
	}
	if res := <-signedOut; res.Outcome != appsession.OutcomeOK {
		t.Fatalf("sign-out = %+v", res)
	}

	if !a.sessionRevoked(issued.Session.ID()) {
		t.Error("the session survived the sign-out")
	}
	if live := a.liveTokens(issued.Session.ID()); live != 0 {
		t.Errorf("%d live tokens: the token issued during the sign-out was not revoked", live)
	}
	if res := a.exchange(refreshed.NewRefreshSecret); res.Outcome != appsession.OutcomeDenied {
		t.Errorf("the new token works after the sign-out: %+v", res)
	}
}
