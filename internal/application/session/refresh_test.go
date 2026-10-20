package session_test

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"go.airlance.org/auth/internal/application/port"
	appsession "go.airlance.org/auth/internal/application/session"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/session"
	"go.airlance.org/auth/internal/domain/token"
	"go.airlance.org/auth/internal/testutil"
)

func TestRefreshRotatesTheToken(t *testing.T) {
	e := newEnv(t)
	issued, user := e.login("alice@example.test")
	e.clock.Advance(day)

	res := e.exchange(issued.RefreshSecret)
	if res.Outcome != appsession.OutcomeOK || res.NewRefreshSecret == "" || res.NewRefreshSecret == issued.RefreshSecret {
		t.Fatalf("result = %+v", res)
	}

	if res.Session.UserID() != user.ID() || res.Session.ID() != issued.Session.ID() {
		t.Errorf("result session = %+v", res.Session.Record())
	}

	if want := t0.Add(day).Add(30 * day); !res.RefreshExpiresAt.Equal(want) {
		t.Errorf("RefreshExpiresAt = %v, want %v", res.RefreshExpiresAt, want)
	}

	tokens := e.tokens(issued.Session.ID())
	if len(tokens) != 2 {
		t.Fatalf("%d tokens, want parent and child", len(tokens))
	}

	parent, child := tokens[0], tokens[1]
	if parent.UsedAt().IsZero() || !parent.RevokedAt().IsZero() {
		t.Errorf("parent = %+v", parent.Record())
	}

	if child.ParentID() != parent.ID() || child.FamilyID() != parent.FamilyID() || !child.UsedAt().IsZero() {
		t.Errorf("child = %+v", child.Record())
	}

	sess := e.session(issued.Session.ID())
	if !sess.LastActiveAt().Equal(t0.Add(day)) || !sess.IdleExpiresAt().Equal(t0.Add(31*day)) {
		t.Errorf("session activity = %v idle until %v", sess.LastActiveAt(), sess.IdleExpiresAt())
	}

	// The new secret works once more, so a chain of exchanges is possible.
	e.clock.Advance(day)

	if again := e.exchange(res.NewRefreshSecret); again.Outcome != appsession.OutcomeOK {
		t.Errorf("second exchange = %+v", again)
	}
}

func TestReplayOfAUsedTokenRevokesTheWholeSession(t *testing.T) {
	e := newEnv(t)
	issued, _ := e.login("alice@example.test")

	first := e.exchange(issued.RefreshSecret)
	if first.Outcome != appsession.OutcomeOK {
		t.Fatalf("first = %+v", first)
	}

	replay := e.exchange(issued.RefreshSecret)
	if replay.Outcome != appsession.OutcomeDenied || replay.Reason != appsession.ReasonTokenReused {
		t.Fatalf("replay = %+v", replay)
	}
	// The revocation is committed together with the denial.
	sess := e.session(issued.Session.ID())
	if sess.RevokedAt().IsZero() || !e.allRevoked(sess.ID()) {
		t.Errorf("revokedAt=%v tokens revoked=%v: a reuse must revoke the session and its tokens", sess.RevokedAt(), e.allRevoked(sess.ID()))
	}
	// The honest holder of the child token is signed out as well.
	if res := e.exchange(first.NewRefreshSecret); res.Outcome != appsession.OutcomeDenied || res.Reason != appsession.ReasonSessionInactive {
		t.Errorf("child after reuse = %+v", res)
	}
}

func TestLostResponseNeedsANewLogin(t *testing.T) {
	// Strict policy (Q4): the client retrying with the old secret after the server
	// rotated it looks exactly like a replay.
	e := newEnv(t)
	issued, _ := e.login("alice@example.test")
	e.exchange(issued.RefreshSecret) // the response is "lost"

	retry := e.exchange(issued.RefreshSecret)
	if retry.Outcome != appsession.OutcomeDenied || retry.Reason != appsession.ReasonTokenReused {
		t.Errorf("retry = %+v", retry)
	}
}

func TestUsedAncestorIsAReuseEvenAfterItsOwnExpiry(t *testing.T) {
	e := newEnv(t)
	issued, _ := e.login("alice@example.test")
	e.clock.Advance(day)

	child := e.exchange(issued.RefreshSecret)
	if child.Outcome != appsession.OutcomeOK {
		t.Fatal("setup exchange failed")
	}

	// The parent expired at day 30; the session, touched on day 1, lives until day 31.
	e.clock.Set(t0.Add(30*day + time.Hour))

	if !e.session(issued.Session.ID()).Active(e.clock.Now()) {
		t.Fatal("setup: the session should still be active")
	}

	res := e.exchange(issued.RefreshSecret)
	if res.Outcome != appsession.OutcomeDenied || res.Reason != appsession.ReasonTokenReused {
		t.Errorf("result = %+v, want a reuse, not a plain expiry", res)
	}

	if e.session(issued.Session.ID()).RevokedAt().IsZero() {
		t.Error("the session was not revoked")
	}
}

func TestExpiredUnusedTokenIsDeniedWithoutRevokingTheSession(t *testing.T) {
	e := newEnv(t)
	user := e.factory.User(testutil.UserSpec{})
	sess := e.factory.Session(testutil.SessionSpec{User: user})
	short := session.Policy{IdleTTL: day, AbsoluteTTL: 90 * day}
	root, secret := e.factory.RefreshToken(testutil.RefreshSpec{Session: sess, Policy: &short}) // expires after one day
	seed(t, e, user, sess, root)

	e.clock.Advance(2 * day)

	res := e.exchange(secret)
	if res.Outcome != appsession.OutcomeDenied || res.Reason != appsession.ReasonTokenExpired {
		t.Fatalf("result = %+v", res)
	}

	if !e.session(sess.ID()).RevokedAt().IsZero() || len(e.tokens(sess.ID())) != 1 {
		t.Error("an expired token must change nothing")
	}
}

func seed(t *testing.T, e *env, user *identity.User, sess *session.Session, tokens ...*token.RefreshToken) {
	t.Helper()

	err := e.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		if _, _, err := st.Users.Ensure(ctx, user); err != nil {
			return err
		}

		if err := st.Sessions.Create(ctx, sess); err != nil {
			return err
		}

		for _, tok := range tokens {
			if err := st.Tokens.Create(ctx, tok); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func TestRevokedUnusedTokenIsDenied(t *testing.T) {
	e := newEnv(t)
	issued, _ := e.login("alice@example.test")
	root := e.tokens(issued.Session.ID())[0] // read outside the transaction: the store lock is not reentrant

	err := e.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		tok, err := st.Tokens.GetForUpdate(ctx, root.ID())
		if err != nil {
			return err
		}

		tok.Revoke(t0)

		return st.Tokens.Save(ctx, tok)
	})
	if err != nil {
		t.Fatal(err)
	}

	res := e.exchange(issued.RefreshSecret)
	if res.Outcome != appsession.OutcomeDenied || res.Reason != appsession.ReasonTokenRevoked {
		t.Errorf("result = %+v", res)
	}

	if !e.session(issued.Session.ID()).RevokedAt().IsZero() {
		t.Error("a revoked token must not revoke the session")
	}
}

func TestRefreshOfInactiveSessionIsDeniedAndMintsNothing(t *testing.T) {
	t.Run("revoked", func(t *testing.T) {
		e := newEnv(t)

		issued, user := e.login("alice@example.test")
		if res, err := e.revoke.Execute(context.Background(), appsession.RevokeSessionCommand{ActorUserID: user.ID(), SessionID: issued.Session.ID().String()}); err != nil || res.Outcome != appsession.OutcomeOK {
			t.Fatalf("revoke = %+v, %v", res, err)
		}

		res := e.exchange(issued.RefreshSecret)
		if res.Outcome != appsession.OutcomeDenied || res.Reason != appsession.ReasonSessionInactive {
			t.Errorf("result = %+v", res)
		}

		if len(e.tokens(issued.Session.ID())) != 1 {
			t.Error("a revoked session received a new token")
		}
	})
	t.Run("idle for too long", func(t *testing.T) {
		e := newEnv(t)
		issued, _ := e.login("alice@example.test")
		e.clock.Advance(30 * day)

		res := e.exchange(issued.RefreshSecret)
		if res.Outcome != appsession.OutcomeDenied || res.Reason != appsession.ReasonSessionInactive {
			t.Errorf("result = %+v", res)
		}
	})
}

func TestTokenLifetimeNeverOutlivesTheSession(t *testing.T) {
	e := newEnv(t)
	issued, _ := e.login("alice@example.test")
	secret := issued.RefreshSecret

	var last appsession.RefreshResult

	for _, d := range []time.Duration{25, 50, 75, 85} {
		e.clock.Set(t0.Add(d * day))

		last = e.exchange(secret)
		if last.Outcome != appsession.OutcomeOK {
			t.Fatalf("exchange at day %d = %+v", d, last)
		}

		secret = last.NewRefreshSecret
	}

	absolute := e.session(issued.Session.ID()).ExpiresAt()
	if !last.RefreshExpiresAt.Equal(absolute) {
		t.Errorf("token expiry %v should be capped at the session end %v", last.RefreshExpiresAt, absolute)
	}

	e.clock.Set(absolute)

	if res := e.exchange(secret); res.Outcome != appsession.OutcomeDenied || res.Reason != appsession.ReasonSessionInactive {
		t.Errorf("exchange at the absolute limit = %+v", res)
	}
}

func TestRefreshRefusesMalformedAndUnknownSecrets(t *testing.T) {
	e := newEnv(t)
	issued, _ := e.login("alice@example.test")
	before := e.store.TokenCount()

	for name, tc := range map[string]struct {
		secret string
		reason appsession.Reason
	}{
		"empty":   {"", appsession.ReasonMalformed},
		"short":   {"abc", appsession.ReasonMalformed},
		"newline": {issued.RefreshSecret + "\n", appsession.ReasonMalformed},
		"unknown": {e.factory.RefreshSecret(), appsession.ReasonUnknownToken},
	} {
		res := e.exchange(tc.secret)
		if res.Outcome != appsession.OutcomeDenied || res.Reason != tc.reason {
			t.Errorf("%s: result = %+v, want denied/%s", name, res, tc.reason)
		}
	}

	if e.store.TokenCount() != before || !e.session(issued.Session.ID()).RevokedAt().IsZero() {
		t.Error("a refused request changed data")
	}
}

func TestTechnicalFailureRollsTheExchangeBack(t *testing.T) {
	e := newEnv(t)
	issued, _ := e.login("alice@example.test")
	before := e.session(issued.Session.ID()).Record()
	e.faults.wrap = func(s port.Stores) port.Stores { s.Tokens = failingTokenCreate{s.Tokens}; return s }

	_, err := e.refresh.Execute(context.Background(), appsession.RefreshCommand{RefreshSecret: issued.RefreshSecret})
	if !errors.Is(err, errBoom) {
		t.Fatalf("error = %v, want boom", err)
	}

	if !reflect.DeepEqual(e.session(issued.Session.ID()).Record(), before) {
		t.Error("the session was touched by a failed exchange")
	}

	if tokens := e.tokens(issued.Session.ID()); len(tokens) != 1 || !tokens[0].UsedAt().IsZero() {
		t.Error("the token was consumed by a failed exchange")
	}

	e.faults.wrap = nil
	if res := e.exchange(issued.RefreshSecret); res.Outcome != appsession.OutcomeOK {
		t.Errorf("retry after a technical failure = %+v: the token must stay usable", res)
	}
}

func TestParallelExchangesOfOneTokenRevokeTheSession(t *testing.T) {
	e := newEnv(t)
	issued, _ := e.login("alice@example.test")

	const workers = 8

	results := make([]appsession.RefreshResult, workers)

	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()

			results[i] = e.exchange(issued.RefreshSecret)
		}()
	}

	wg.Wait()

	var ok *appsession.RefreshResult

	for i := range results {
		if results[i].Outcome == appsession.OutcomeOK {
			if ok != nil {
				t.Fatal("two parallel exchanges both succeeded")
			}

			ok = &results[i]
		}
	}

	if ok == nil {
		t.Fatal("no exchange succeeded")
	}
	// Strict policy: the duplicates look like a replay, so the session ends and the
	// child that was just issued is dead too.
	if e.session(issued.Session.ID()).RevokedAt().IsZero() {
		t.Error("the session survived parallel use of one token")
	}

	if res := e.exchange(ok.NewRefreshSecret); res.Outcome != appsession.OutcomeDenied {
		t.Errorf("the child of a raced token still works: %+v", res)
	}
}

func TestOneDevicesReuseDoesNotAffectAnother(t *testing.T) {
	e := newEnv(t)
	laptop, user := e.login("alice@example.test")
	phone := e.loginAgain(user)

	e.exchange(laptop.RefreshSecret)
	e.exchange(laptop.RefreshSecret) // replay on the laptop

	if e.session(laptop.Session.ID()).RevokedAt().IsZero() {
		t.Error("the laptop session should be revoked")
	}

	if !e.session(phone.Session.ID()).RevokedAt().IsZero() {
		t.Error("the phone session must stay independent")
	}

	if res := e.exchange(phone.RefreshSecret); res.Outcome != appsession.OutcomeOK {
		t.Errorf("phone refresh = %+v", res)
	}
}

func TestNewRefreshRequiresDependencies(t *testing.T) {
	e := newEnv(t)

	good := appsession.RefreshDeps{UnitOfWork: e.faults, Clock: e.clock, TokenIDs: e.ids, Secrets: e.secrets, Signer: e.signer, Metrics: e.metrics, Policy: policy}
	for name, mutate := range map[string]func(*appsession.RefreshDeps){
		"unit of work": func(d *appsession.RefreshDeps) { d.UnitOfWork = nil },
		"clock":        func(d *appsession.RefreshDeps) { d.Clock = nil },
		"token ids":    func(d *appsession.RefreshDeps) { d.TokenIDs = nil },
		"secrets":      func(d *appsession.RefreshDeps) { d.Secrets = nil },
		"signer":       func(d *appsession.RefreshDeps) { d.Signer = nil },
		"metrics":      func(d *appsession.RefreshDeps) { d.Metrics = nil },
		"policy":       func(d *appsession.RefreshDeps) { d.Policy = session.Policy{} },
	} {
		d := good
		mutate(&d)

		if _, err := appsession.NewRefresh(d); err == nil {
			t.Errorf("NewRefresh accepted a missing %s", name)
		}
	}
}

func TestRefreshIssuesAnAccessTokenForTheSession(t *testing.T) {
	e := newEnv(t)
	issued, user := e.login("alice@example.test")
	e.clock.Advance(time.Hour)

	res := e.exchange(issued.RefreshSecret)
	if res.Outcome != appsession.OutcomeOK || res.Access.Value == "" {
		t.Fatalf("result = %+v", res)
	}

	if want := e.clock.Now().Add(5 * time.Minute); !res.Access.ExpiresAt.Equal(want) {
		t.Errorf("access expires %v, want %v", res.Access.ExpiresAt, want)
	}

	claims, err := e.verify.VerifyAccess(res.Access.Value)
	if err != nil {
		t.Fatalf("the issued access token does not verify: %v", err)
	}

	if claims.UserID != user.ID() || claims.SessionID != issued.Session.ID() || !claims.AuthTime.Equal(issued.Session.AuthTime()) ||
		len(claims.AMR) != 1 || claims.AMR[0] != "otp" {
		t.Errorf("claims = %+v", claims)
	}
}

func TestRefusedRefreshIssuesNoAccessToken(t *testing.T) {
	e := newEnv(t)
	issued, _ := e.login("alice@example.test")
	e.exchange(issued.RefreshSecret)

	for name, secret := range map[string]string{"replay": issued.RefreshSecret, "unknown": e.factory.RefreshSecret(), "malformed": "x"} {
		if res := e.exchange(secret); res.Outcome != appsession.OutcomeDenied || res.Access.Value != "" {
			t.Errorf("%s: result = %+v", name, res)
		}
	}
}

type failingSigner struct{}

func (failingSigner) SignAccess(port.AccessClaims) (port.AccessToken, error) {
	return port.AccessToken{}, errBoom
}

func TestSigningFailureRollsTheExchangeBack(t *testing.T) {
	e := newEnv(t)
	issued, _ := e.login("alice@example.test")
	before := e.session(issued.Session.ID()).Record()

	failing, err := appsession.NewRefresh(appsession.RefreshDeps{
		UnitOfWork: e.faults, Clock: e.clock, TokenIDs: e.ids, Secrets: e.secrets, Signer: failingSigner{}, Metrics: e.metrics, Policy: policy,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = failing.Execute(context.Background(), appsession.RefreshCommand{RefreshSecret: issued.RefreshSecret})
	if !errors.Is(err, errBoom) {
		t.Fatalf("error = %v, want boom", err)
	}

	if !reflect.DeepEqual(e.session(issued.Session.ID()).Record(), before) {
		t.Error("the session was touched although no access token could be issued")
	}

	if tokens := e.tokens(issued.Session.ID()); len(tokens) != 1 || !tokens[0].UsedAt().IsZero() {
		t.Error("the refresh token was consumed although signing failed")
	}

	if res := e.exchange(issued.RefreshSecret); res.Outcome != appsession.OutcomeOK {
		t.Errorf("retry = %+v: the token must stay usable", res)
	}
}

func TestReuseIsAuditedAndAnOrdinaryRefreshIsNot(t *testing.T) {
	e := newEnv(t)
	issued, user := e.login("alice@example.test")
	e.exchange(issued.RefreshSecret)

	if len(e.store.AuditEvents()) != 0 {
		t.Fatal("an ordinary refresh must not be audited: it is the highest-volume operation")
	}

	e.exchange(issued.RefreshSecret) // replay

	events := e.store.AuditEvents()
	if len(events) != 1 {
		t.Fatalf("%d events, want one reuse event", len(events))
	}

	ev := events[0]
	if ev.Type != port.AuditRefreshReuse || ev.Result != port.AuditDenied || ev.UserID != user.ID() ||
		ev.SessionID != issued.Session.ID() || ev.Fields["reason"] != "token_reused" {
		t.Errorf("event = %+v", ev)
	}
}

func TestReuseIsCountedOnceAfterTheCommit(t *testing.T) {
	e := newEnv(t)
	issued, _ := e.login("alice@example.test")
	e.exchange(issued.RefreshSecret)

	if e.metrics.reuses != 0 {
		t.Fatalf("an ordinary refresh was counted as a reuse")
	}

	e.exchange(issued.RefreshSecret)

	if e.metrics.reuses != 1 {
		t.Errorf("reuses = %d, want 1", e.metrics.reuses)
	}

	e.exchange(issued.RefreshSecret) // the session is already revoked: not a new revocation

	if e.metrics.reuses != 1 {
		t.Errorf("reuses = %d after a replay on a revoked session, want 1", e.metrics.reuses)
	}
}

func TestARolledBackReuseIsNotCounted(t *testing.T) {
	e := newEnv(t)
	issued, _ := e.login("alice@example.test")
	e.exchange(issued.RefreshSecret)
	e.faults.wrap = func(s port.Stores) port.Stores { s.Audit = failingAudit{}; return s }

	if _, err := e.refresh.Execute(context.Background(), appsession.RefreshCommand{RefreshSecret: issued.RefreshSecret}); !errors.Is(err, errBoom) {
		t.Fatalf("error = %v, want boom", err)
	}

	if e.metrics.reuses != 0 {
		t.Errorf("reuses = %d: a revocation that was rolled back did not happen", e.metrics.reuses)
	}

	if !e.session(issued.Session.ID()).RevokedAt().IsZero() {
		t.Error("the revocation survived the rolled back transaction")
	}
}

type failingAudit struct{}

func (failingAudit) Record(context.Context, port.AuditEvent) error { return errBoom }
