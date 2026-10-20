package admin_test

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"go.airlance.org/auth/internal/application/admin"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/operator"
	"go.airlance.org/auth/internal/testutil"
)

func TestOperatorEnrollsSignsInAndOut(t *testing.T) {
	e := newEnv(t)
	f := e.enrolled("Ops@Example.test")

	res := e.login(f)
	if res.Outcome != admin.OutcomeOK || res.SessionSecret == "" || res.Operator.Email().String() != "ops@example.test" {
		t.Fatalf("login = %+v", res)
	}

	if want := t0.Add(operator.IdleTimeout); !res.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", res.ExpiresAt, want)
	}

	auth, err := e.auth.Authenticate(context.Background(), res.SessionSecret)
	must(t, err)

	if auth.Outcome != admin.OutcomeOK || auth.Actor.OperatorID != f.op.ID() || auth.CSRFToken != operator.CSRFToken(res.SessionSecret) {
		t.Fatalf("Authenticate = %+v", auth)
	}

	must(t, e.auth.Logout(context.Background(), auth.Actor))
	after, err := e.auth.Authenticate(context.Background(), res.SessionSecret)
	must(t, err)

	if after.Outcome != admin.OutcomeUnauthenticated {
		t.Errorf("Authenticate after Logout = %v", after.Outcome)
	}

	must(t, e.auth.Logout(context.Background(), auth.Actor)) // a second logout is not an error

	if got := e.auditOf(port.AuditOperatorEnrolled); len(got) != 1 || got[0].OperatorID != f.op.ID() {
		t.Errorf("enrolled audit = %+v", got)
	}

	if got := e.auditOf(port.AuditOperatorLogin); len(got) != 1 || got[0].Result != port.AuditSuccess || got[0].OperatorID != f.op.ID() {
		t.Errorf("login audit = %+v", got)
	}
}

func TestEnrollmentCodeIsRefusedUnlessItIsLiveAndUnused(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	_, fresh, err := e.operators.Create(ctx, "ops@example.test")
	must(t, err)
	_, stale, err := e.operators.Create(ctx, "stale@example.test")
	must(t, err)
	e.clock.Advance(operator.EnrollmentTTL)
	_, live, err := e.operators.Create(ctx, "live@example.test")
	must(t, err)

	for name, code := range map[string]string{
		"not a code":     "hello",
		"empty":          "",
		"unknown":        strings.Repeat("A", 43),
		"expired":        stale.Code,
		"too long":       fresh.Code + "A",
		"newline suffix": live.Code + "\n",
	} {
		res, err := e.auth.BeginEnroll(ctx, admin.BeginEnrollCommand{Code: code, ClientIP: ip})
		must(t, err)

		if res.Outcome != admin.OutcomeDenied || res.Reason != admin.ReasonBadCode || res.ChallengeID != "" {
			t.Errorf("%s: BeginEnroll = %+v", name, res)
		}
	}

	if res, err := e.auth.BeginEnroll(ctx, admin.BeginEnrollCommand{Code: live.Code, ClientIP: ip}); err != nil || res.Outcome != admin.OutcomeOK {
		t.Errorf("a live code: %+v, %v", res, err)
	}
}

func TestEnrollmentCodeWorksOnceAndOnlyAStoredKeySpendsIt(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	_, enrollment, err := e.operators.Create(ctx, "ops@example.test")
	must(t, err)

	// A ceremony that fails (the authenticator talks to another origin) spends the challenge, not the code.
	wrong := testutil.NewSoftAuthenticator(t, rpID, "https://evil.example.test")
	begin, err := e.auth.BeginEnroll(ctx, admin.BeginEnrollCommand{Code: enrollment.Code, ClientIP: ip})
	must(t, err)
	failed, err := e.auth.FinishEnroll(ctx, admin.FinishEnrollCommand{ChallengeID: begin.ChallengeID, Response: wrong.Register(begin.Options), ClientIP: ip})
	must(t, err)

	if failed.Outcome != admin.OutcomeDenied || failed.Reason != admin.ReasonCeremonyFailed {
		t.Fatalf("a wrong-origin registration = %+v", failed)
	}

	again, err := e.auth.FinishEnroll(ctx, admin.FinishEnrollCommand{ChallengeID: begin.ChallengeID, Response: wrong.Register(begin.Options), ClientIP: ip})
	must(t, err)

	if again.Outcome != admin.OutcomeDenied || again.Reason != admin.ReasonBadChallenge {
		t.Errorf("the spent challenge was accepted again: %+v", again)
	}

	good := testutil.NewSoftAuthenticator(t, rpID, origin)
	begin, err = e.auth.BeginEnroll(ctx, admin.BeginEnrollCommand{Code: enrollment.Code, ClientIP: ip})
	must(t, err)

	if begin.Outcome != admin.OutcomeOK {
		t.Fatalf("the code was spent by a failed ceremony: %+v", begin)
	}

	done, err := e.auth.FinishEnroll(ctx, admin.FinishEnrollCommand{ChallengeID: begin.ChallengeID, Response: good.Register(begin.Options), Name: "Laptop", ClientIP: ip})
	must(t, err)

	if done.Outcome != admin.OutcomeOK {
		t.Fatalf("FinishEnroll = %+v", done)
	}

	res, err := e.auth.BeginEnroll(ctx, admin.BeginEnrollCommand{Code: enrollment.Code, ClientIP: ip})
	must(t, err)

	if res.Outcome != admin.OutcomeDenied || res.Reason != admin.ReasonBadCode {
		t.Errorf("a spent code started another ceremony: %+v", res)
	}

	keys, err := e.operators.List(ctx)
	must(t, err)

	if len(keys) != 1 || keys[0].Keys != 1 {
		t.Errorf("operators = %+v, want one key", keys)
	}
}

func TestEnrollmentChallengeIsBoundToItsPurposeAndCode(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	_, a, err := e.operators.Create(ctx, "a@example.test")
	must(t, err)

	// A login challenge cannot finish an enrollment.
	login, err := e.auth.BeginLogin(ctx, admin.BeginLoginCommand{ClientIP: ip})
	must(t, err)
	key := testutil.NewSoftAuthenticator(t, rpID, origin)
	beginA, err := e.auth.BeginEnroll(ctx, admin.BeginEnrollCommand{Code: a.Code, ClientIP: ip})
	must(t, err)
	res, err := e.auth.FinishEnroll(ctx, admin.FinishEnrollCommand{ChallengeID: login.ChallengeID, Response: key.Register(beginA.Options), ClientIP: ip})
	must(t, err)

	if res.Outcome != admin.OutcomeDenied || res.Reason != admin.ReasonBadChallenge {
		t.Errorf("a login challenge finished an enrollment: %+v", res)
	}
	// An enrollment challenge cannot finish a login.
	fin, err := e.auth.FinishLogin(ctx, admin.FinishLoginCommand{ChallengeID: beginA.ChallengeID, Response: key.Assert(login.Options), ClientIP: ip})
	must(t, err)

	if fin.Outcome != admin.OutcomeDenied || fin.Reason != admin.ReasonBadChallenge {
		t.Errorf("an enrollment challenge finished a login: %+v", fin)
	}
	// Garbage identifiers are the same refusal.
	for _, id := range []string{"", "nope", strings.Repeat("0", 36)} {
		if r, err := e.auth.FinishEnroll(ctx, admin.FinishEnrollCommand{ChallengeID: id, Response: []byte("{}"), ClientIP: ip}); err != nil || r.Reason != admin.ReasonBadChallenge {
			t.Errorf("FinishEnroll(%q) = %+v, %v", id, r, err)
		}

		if r, err := e.auth.FinishLogin(ctx, admin.FinishLoginCommand{ChallengeID: id, Response: []byte("{}"), ClientIP: ip}); err != nil || r.Reason != admin.ReasonBadChallenge {
			t.Errorf("FinishLogin(%q) = %+v, %v", id, r, err)
		}
	}
}

func TestEnrollRejectsABadKeyNameBeforeAnyWork(t *testing.T) {
	ctx := context.Background()

	e := newEnv(t)
	for _, name := range []string{strings.Repeat("x", 65), "bad\nname"} {
		_, err := e.auth.FinishEnroll(ctx, admin.FinishEnrollCommand{ChallengeID: "x", Response: []byte("{}"), Name: name, ClientIP: ip})
		if err == nil || !strings.Contains(err.Error(), admin.ErrInvalidInput.Error()) {
			t.Errorf("name %q: error = %v, want ErrInvalidInput", name, err)
		}
	}
}

func TestAnOperatorHasAtMostFiveKeys(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	f := e.enrolled("ops@example.test")
	for i := 1; i < operator.MaxCredentials; i++ {
		_, enrollment, err := e.operators.Enroll(ctx, "ops@example.test")
		must(t, err)
		key := testutil.NewSoftAuthenticator(t, rpID, origin)
		begin, err := e.auth.BeginEnroll(ctx, admin.BeginEnrollCommand{Code: enrollment.Code, ClientIP: ip})
		must(t, err)
		res, err := e.auth.FinishEnroll(ctx, admin.FinishEnrollCommand{ChallengeID: begin.ChallengeID, Response: key.Register(begin.Options), ClientIP: ip})
		must(t, err)

		if res.Outcome != admin.OutcomeOK {
			t.Fatalf("key %d: %+v", i+1, res)
		}
	}

	_, enrollment, err := e.operators.Enroll(ctx, "ops@example.test")
	must(t, err)
	res, err := e.auth.BeginEnroll(ctx, admin.BeginEnrollCommand{Code: enrollment.Code, ClientIP: ip})
	must(t, err)

	if res.Outcome != admin.OutcomeConflict || res.Reason != admin.ReasonTooManyKeys {
		t.Errorf("a sixth key: %+v", res)
	}

	_ = f
}

func TestAnUnknownKeyCannotSignIn(t *testing.T) {
	e := newEnv(t)
	e.enrolled("ops@example.test")

	stranger := operatorFixture{auth: testutil.NewSoftAuthenticator(t, rpID, origin)}
	// The stranger registered nowhere: its handle and credential are unknown.
	stranger.auth.UserHandle = []byte("0123456789abcdef")

	res := e.login(stranger)
	if res.Outcome != admin.OutcomeDenied || res.Reason != admin.ReasonCeremonyFailed || res.SessionSecret != "" {
		t.Errorf("an unknown key: %+v", res)
	}
}

func TestACopiedKeyIsRefusedAndRemembered(t *testing.T) {
	e := newEnv(t)
	f := e.enrolled("ops@example.test")

	f.auth.SignCount = 10
	if res := e.login(f); res.Outcome != admin.OutcomeOK {
		t.Fatalf("first login: %+v", res)
	}

	f.auth.SignCount = 3 // the next Assert reports 4: the counter went back

	res := e.login(f)
	if res.Outcome != admin.OutcomeDenied || res.Reason != admin.ReasonCloneSuspected {
		t.Fatalf("a rewound counter: %+v", res)
	}

	denied := 0

	for _, ev := range e.auditOf(port.AuditOperatorLogin) {
		if ev.Result == port.AuditDenied && ev.OperatorID == f.op.ID() && ev.Fields["reason"] == port.CloneSuspectedReason {
			denied++

			if !ev.Lasting() {
				t.Error("a clone refusal is not kept for the long retention")
			}
		}
	}

	if denied != 1 {
		t.Errorf("clone refusals in the audit log = %d, want 1", denied)
	}
}

func TestADisabledOperatorCannotEnrollSignInOrUseASession(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	in := e.signedIn("ops@example.test")
	_, pending, err := e.operators.Enroll(ctx, "ops@example.test")
	must(t, err)

	_, err = e.operators.SetDisabled(ctx, "ops@example.test", true)
	must(t, err)

	if r, err := e.auth.Authenticate(ctx, in.secret); err != nil || r.Outcome != admin.OutcomeUnauthenticated {
		t.Errorf("the open session still works: %+v, %v", r, err)
	}

	if r, err := e.auth.BeginEnroll(ctx, admin.BeginEnrollCommand{Code: pending.Code, ClientIP: ip}); err != nil || r.Outcome != admin.OutcomeDenied || r.Reason != admin.ReasonOperatorOff {
		t.Errorf("a disabled operator started an enrollment: %+v, %v", r, err)
	}

	res := e.login(in.operatorFixture)
	if res.Outcome != admin.OutcomeDenied || res.Reason != admin.ReasonOperatorOff {
		t.Errorf("a disabled operator signed in: %+v", res)
	}

	if _, _, err := e.operators.Enroll(ctx, "ops@example.test"); err == nil {
		t.Error("a code was issued to a disabled operator")
	}

	_, err = e.operators.SetDisabled(ctx, "ops@example.test", false)
	must(t, err)

	if res := e.login(in.operatorFixture); res.Outcome != admin.OutcomeOK {
		t.Errorf("an enabled operator cannot sign in: %+v", res)
	}
	// The session that was ended stays ended.
	if r, err := e.auth.Authenticate(ctx, in.secret); err != nil || r.Outcome != admin.OutcomeUnauthenticated {
		t.Errorf("a revoked session came back: %+v, %v", r, err)
	}
}

func TestSessionLifetimes(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	f := e.enrolled("ops@example.test")
	secret := func() string {
		res := e.login(f)
		if res.Outcome != admin.OutcomeOK {
			t.Fatalf("login: %+v", res)
		}

		return res.SessionSecret
	}
	status := func(secret string) admin.Outcome {
		r, err := e.auth.Authenticate(ctx, secret)
		must(t, err)

		return r.Outcome
	}

	t.Run("use keeps a session alive, idleness ends it", func(t *testing.T) {
		s := secret()

		for i := 0; i < 3; i++ {
			e.clock.Advance(operator.IdleTimeout - time.Minute)

			if status(s) != admin.OutcomeOK {
				t.Fatalf("a used session ended at step %d", i)
			}
		}

		e.clock.Advance(operator.IdleTimeout)

		if status(s) != admin.OutcomeUnauthenticated {
			t.Error("an idle session is still accepted")
		}
	})

	t.Run("the absolute lifetime ends a busy session", func(t *testing.T) {
		s := secret()

		for elapsed := time.Duration(0); elapsed < operator.MaxAge; elapsed += 20 * time.Minute {
			e.clock.Advance(20 * time.Minute)

			if elapsed+20*time.Minute < operator.MaxAge && status(s) != admin.OutcomeOK {
				t.Fatalf("a busy session ended after %v", elapsed+20*time.Minute)
			}
		}

		e.clock.Advance(time.Minute)

		if status(s) != admin.OutcomeUnauthenticated {
			t.Error("a session past MaxAge is still accepted")
		}
	})

	t.Run("a secret that cannot be one is not accepted", func(t *testing.T) {
		for _, s := range []string{"", "x", strings.Repeat("A", 43), strings.Repeat("A", 44)} {
			if status(s) != admin.OutcomeUnauthenticated {
				t.Errorf("secret %q accepted", s)
			}
		}
	})

	t.Run("two sessions are independent", func(t *testing.T) {
		a, b := secret(), secret()
		r, err := e.auth.Authenticate(ctx, a)
		must(t, err)
		must(t, e.auth.Logout(ctx, r.Actor))

		if status(a) != admin.OutcomeUnauthenticated || status(b) != admin.OutcomeOK {
			t.Error("logging out one session affected the other")
		}
	})
}

func TestACeremonyChallengeExpires(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	f := e.enrolled("ops@example.test")
	begin, err := e.auth.BeginLogin(ctx, admin.BeginLoginCommand{ClientIP: ip})
	must(t, err)
	e.clock.Advance(5 * time.Minute)
	res, err := e.auth.FinishLogin(ctx, admin.FinishLoginCommand{ChallengeID: begin.ChallengeID, Response: f.auth.Assert(begin.Options), ClientIP: ip})
	must(t, err)

	if res.Outcome != admin.OutcomeDenied || res.Reason != admin.ReasonBadChallenge {
		t.Errorf("an expired challenge: %+v", res)
	}
}

// unknownChallenge is a well-formed identifier no ceremony ever got.
const unknownChallenge = "0199c0de-0000-7000-8000-000000000001"

func TestAdminCeremoniesShareAPerAddressBudget(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, tightAdminQuota(t, 3))
	other := netip.MustParseAddr("203.0.113.9")

	for i := 0; i < 3; i++ {
		if r, err := e.auth.BeginLogin(ctx, admin.BeginLoginCommand{ClientIP: ip}); err != nil || r.Outcome != admin.OutcomeOK {
			t.Fatalf("begin %d: %+v, %v", i, r, err)
		}
	}

	r, err := e.auth.BeginLogin(ctx, admin.BeginLoginCommand{ClientIP: ip})
	must(t, err)

	if r.Outcome != admin.OutcomeRateLimited || r.Reason != admin.ReasonQuota || r.ChallengeID != "" {
		t.Errorf("the fourth begin: %+v", r)
	}
	// Finishing spends the same budget and refuses before reading anything.
	fin, err := e.auth.FinishLogin(ctx, admin.FinishLoginCommand{ChallengeID: unknownChallenge, Response: []byte("{}"), ClientIP: ip})
	must(t, err)

	if fin.Outcome != admin.OutcomeRateLimited {
		t.Errorf("FinishLogin over the budget: %+v", fin)
	}

	en, err := e.auth.FinishEnroll(ctx, admin.FinishEnrollCommand{ChallengeID: unknownChallenge, Response: []byte("{}"), ClientIP: ip})
	must(t, err)

	if en.Outcome != admin.OutcomeRateLimited {
		t.Errorf("FinishEnroll over the budget: %+v", en)
	}

	be, err := e.auth.BeginEnroll(ctx, admin.BeginEnrollCommand{Code: strings.Repeat("A", 43), ClientIP: ip})
	must(t, err)

	if be.Outcome != admin.OutcomeRateLimited {
		t.Errorf("BeginEnroll over the budget: %+v", be)
	}
	// Another address has its own.
	if r, err := e.auth.BeginLogin(ctx, admin.BeginLoginCommand{ClientIP: other}); err != nil || r.Outcome != admin.OutcomeOK {
		t.Errorf("another address: %+v, %v", r, err)
	}
}

type failingAudit struct{ port.AuditLog }

func (failingAudit) Record(context.Context, port.AuditEvent) error {
	return errBoom
}

func TestASignInThatCannotBeAuditedLeavesNothingBehind(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	f := e.enrolled("ops@example.test")
	begin, err := e.auth.BeginLogin(ctx, admin.BeginLoginCommand{ClientIP: ip})
	must(t, err)

	response := f.auth.Assert(begin.Options)

	e.faults.wrap = func(s port.Stores) port.Stores { s.Audit = failingAudit{s.Audit}; return s }
	if _, err := e.auth.FinishLogin(ctx, admin.FinishLoginCommand{ChallengeID: begin.ChallengeID, Response: response, ClientIP: ip}); err == nil {
		t.Fatal("FinishLogin hid the audit failure")
	}

	e.faults.wrap = nil

	// Everything rolled back: the challenge is unspent and no session exists, so the same answer still works.
	res, err := e.auth.FinishLogin(ctx, admin.FinishLoginCommand{ChallengeID: begin.ChallengeID, Response: response, ClientIP: ip})
	must(t, err)

	if res.Outcome != admin.OutcomeOK {
		t.Errorf("after the rollback: %+v", res)
	}

	if got := e.auditOf(port.AuditOperatorLogin); len(got) != 1 {
		t.Errorf("login audit events = %d, want 1", len(got))
	}
}
