package passkey_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"airlance.org/auth/internal/application/passkey"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/authflow"
	"airlance.org/auth/internal/domain/identity"
	dpasskey "airlance.org/auth/internal/domain/passkey"
	"airlance.org/auth/internal/testutil"
)

func TestPasskeyAloneSignsIn(t *testing.T) {
	e := newEnv(t)
	holder := e.enroll()
	sessions := e.store.SessionCount()
	e.clock.Advance(time.Hour)

	// A client without a binding gets a new one.
	got := e.signIn(holder.auth, "", bindingSecret{})
	if got.Outcome != passkey.OutcomeOK {
		t.Fatalf("result = %+v", got)
	}
	if !slices.Equal(got.Session.AMR(), []string{"passkey"}) || got.User.ID() != holder.user.ID() {
		t.Errorf("session = %v for %v", got.Session.AMR(), got.User.ID())
	}
	if got.NewBindingSecret == "" {
		t.Error("no binding was issued to a client that had none")
	}
	hash, err := e.binding.HashBinding(got.NewBindingSecret)
	if err != nil || got.Session.Binding() != hash {
		t.Errorf("the session is not bound to the issued binding: %v", err)
	}
	if e.store.SessionCount() != sessions+1 {
		t.Errorf("%d sessions, want %d", e.store.SessionCount(), sessions+1)
	}
	claims, err := e.verify.VerifyAccess(got.Access.Value)
	if err != nil || !slices.Equal(claims.AMR, []string{"passkey"}) {
		t.Errorf("claims = %+v, %v", claims, err)
	}

	// A client that has one keeps it.
	b := e.newBinding()
	kept := e.signIn(holder.auth, "", b)
	if kept.Outcome != passkey.OutcomeOK || kept.NewBindingSecret != "" || kept.Session.Binding() != b.hash {
		t.Errorf("with a binding = %+v", kept)
	}

	creds := e.credentials(holder.user)
	if creds[0].SignCount() != 2 || !creds[0].LastUsedAt().Equal(e.clock.Now()) {
		t.Errorf("credential after use = count %d, last used %v", creds[0].SignCount(), creds[0].LastUsedAt())
	}
	if e.signIn(holder.auth, "", bindingSecret{secret: "bad"}).Reason != passkey.ReasonBadBinding {
		t.Error("a malformed binding was accepted")
	}
}

func TestAClientTheAccountHasNotUsedGetsANoticeAndAKnownOneDoesNot(t *testing.T) {
	e := newEnv(t)
	notices := func() []port.MailJob {
		var out []port.MailJob
		for _, j := range e.store.OutboxJobs() {
			if j.Kind == port.JobNewDevice {
				out = append(out, j)
			}
		}
		return out
	}
	holder := e.enroll()
	if n := len(notices()); n != 0 {
		t.Fatalf("the first sign-in of an account queued %d notices", n)
	}
	e.clock.Advance(time.Hour)

	// A client with no binding is a new one: it is told with its label, its address and the time.
	first := e.signIn(holder.auth, "", bindingSecret{})
	if first.Outcome != passkey.OutcomeOK {
		t.Fatalf("result = %+v", first)
	}
	got := notices()
	if len(got) != 1 || got[0].UserID != holder.user.ID() || got[0].DeviceName != "test" || got[0].ClientIP != clientAddr ||
		!got[0].EventAt.Equal(e.clock.Now()) || got[0].QuotaClass != authflow.QuotaRecognized {
		t.Fatalf("notices = %+v", got)
	}

	// The same client again is known, however many times it signs in.
	again := bindingSecret{secret: first.NewBindingSecret}
	e.clock.Advance(time.Hour)
	if r := e.signIn(holder.auth, "", again); r.Outcome != passkey.OutcomeOK {
		t.Fatalf("result = %+v", r)
	}
	if n := len(notices()); n != 1 {
		t.Errorf("a known client made %d notices in all", n)
	}

	// Another binding is another client.
	e.clock.Advance(time.Hour)
	if r := e.signIn(holder.auth, "", e.newBinding()); r.Outcome != passkey.OutcomeOK {
		t.Fatalf("result = %+v", r)
	}
	if n := len(notices()); n != 2 {
		t.Errorf("%d notices after a second new client, want 2", n)
	}
}

func TestSecondFactorCompletesAnEmailSignIn(t *testing.T) {
	e := newEnv(t)
	holder := e.enroll()
	b := e.newBinding()
	ticket := e.ticketFor(holder.user, dpasskey.TicketSecondFactor, b)

	got := e.signIn(holder.auth, ticket, b)
	if got.Outcome != passkey.OutcomeOK {
		t.Fatalf("result = %+v", got)
	}
	if !slices.Equal(got.Session.AMR(), []string{"otp", "passkey"}) || got.Session.Binding() != b.hash || got.NewBindingSecret != "" {
		t.Errorf("session = %v, binding match %v, new binding %q", got.Session.AMR(), got.Session.Binding() == b.hash, got.NewBindingSecret)
	}

	again := e.signIn(holder.auth, ticket, b)
	if again.Outcome != passkey.OutcomeDenied || again.Reason != passkey.ReasonBadTicket {
		t.Errorf("a second sign-in with the same ticket = %+v", again)
	}
}

func TestSecondFactorRefusals(t *testing.T) {
	t.Run("another client's binding", func(t *testing.T) {
		e := newEnv(t)
		holder := e.enroll()
		ticket := e.ticketFor(holder.user, dpasskey.TicketSecondFactor, e.newBinding())
		got := e.signIn(holder.auth, ticket, e.newBinding())
		if got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonBadTicket {
			t.Errorf("result = %+v", got)
		}
	})

	t.Run("no binding at all", func(t *testing.T) {
		e := newEnv(t)
		holder := e.enroll()
		ticket := e.ticketFor(holder.user, dpasskey.TicketSecondFactor, e.newBinding())
		if got := e.signIn(holder.auth, ticket, bindingSecret{}); got.Outcome != passkey.OutcomeDenied {
			t.Errorf("result = %+v: a ticket is useless without its binding", got)
		}
	})

	t.Run("an enroll ticket is not a second factor", func(t *testing.T) {
		e := newEnv(t)
		holder := e.enroll()
		b := e.newBinding()
		ticket := e.ticketFor(holder.user, dpasskey.TicketEnroll, b)
		if got := e.signIn(holder.auth, ticket, b); got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonBadTicket {
			t.Errorf("result = %+v", got)
		}
	})

	t.Run("an expired ticket", func(t *testing.T) {
		e := newEnv(t)
		holder := e.enroll()
		b := e.newBinding()
		ticket := e.ticketFor(holder.user, dpasskey.TicketSecondFactor, b)
		e.clock.Advance(dpasskey.SecondFactorTicketTTL)
		if got := e.signIn(holder.auth, ticket, b); got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonBadTicket {
			t.Errorf("result = %+v", got)
		}
	})

	t.Run("a valid key of another user", func(t *testing.T) {
		e := newEnv(t)
		victim, intruder := e.enroll(), e.enroll()
		b := e.newBinding()
		// The email code proved the victim; the intruder's own key must not complete it.
		ticket := e.ticketFor(victim.user, dpasskey.TicketSecondFactor, b)
		before := e.store.SessionCount()
		got := e.signIn(intruder.auth, ticket, b)
		if got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonUnknownKey {
			t.Fatalf("result = %+v", got)
		}
		if e.store.SessionCount() != before {
			t.Error("a session opened for a key that does not belong to the proven user")
		}
		// The ticket is not spent: the victim's own key still completes it.
		if ok := e.signIn(victim.auth, ticket, b); ok.Outcome != passkey.OutcomeOK || ok.User.ID() != victim.user.ID() {
			t.Errorf("the owner's key afterwards = %+v", ok)
		}
	})
}

func TestLoginRefusals(t *testing.T) {
	login := func(e *env, auth *testutil.SoftAuthenticator) passkey.FinishLoginResult {
		return e.signIn(auth, "", e.newBinding())
	}

	t.Run("a key nobody registered", func(t *testing.T) {
		e := newEnv(t)
		e.enroll()
		stranger := testutil.NewSoftAuthenticator(t, rpID, origin)
		stranger.UserHandle = []byte("0123456789abcdef")
		if got := login(e, stranger); got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonCeremonyFailed {
			t.Errorf("result = %+v", got)
		}
	})

	t.Run("a registered key under another user's handle", func(t *testing.T) {
		e := newEnv(t)
		victim, intruder := e.enroll(), e.enroll()
		forged := *intruder.auth
		forged.UserHandle = dpasskey.UserHandle(victim.user.ID())
		before := e.store.SessionCount()
		if got := login(e, &forged); got.Outcome != passkey.OutcomeDenied {
			t.Errorf("result = %+v", got)
		}
		if e.store.SessionCount() != before {
			t.Error("a key was accepted under another user's name")
		}
	})

	t.Run("a replayed assertion", func(t *testing.T) {
		e := newEnv(t)
		holder := e.enroll()
		begun, _ := e.beginLogin.Execute(context.Background(), passkey.BeginLoginCommand{})
		response := holder.auth.Assert(begun.Options)
		cmd := passkey.FinishLoginCommand{ChallengeID: begun.ChallengeID, Response: response, BindingSecret: e.newBinding().secret}
		first, err := e.finishLogin.Execute(context.Background(), cmd)
		if err != nil || first.Outcome != passkey.OutcomeOK {
			t.Fatalf("first = %+v, %v", first, err)
		}
		again, err := e.finishLogin.Execute(context.Background(), cmd)
		if err != nil || again.Outcome != passkey.OutcomeDenied || again.Reason != passkey.ReasonBadChallenge {
			t.Errorf("replay = %+v, %v", again, err)
		}
	})

	t.Run("an expired challenge", func(t *testing.T) {
		e := newEnv(t)
		holder := e.enroll()
		begun, _ := e.beginLogin.Execute(context.Background(), passkey.BeginLoginCommand{})
		response := holder.auth.Assert(begun.Options)
		e.clock.Advance(dpasskey.ChallengeTTL)
		got, _ := e.finishLogin.Execute(context.Background(), passkey.FinishLoginCommand{ChallengeID: begun.ChallengeID, Response: response})
		if got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonBadChallenge {
			t.Errorf("result = %+v", got)
		}
	})

	t.Run("a registration challenge cannot sign in", func(t *testing.T) {
		e := newEnv(t)
		holder := e.enroll()
		user := e.newUser()
		b := e.newBinding()
		begun, _ := e.beginEnroll.Execute(context.Background(), passkey.BeginEnrollCommand{
			TicketSecret: e.ticketFor(user, dpasskey.TicketEnroll, b), BindingSecret: b.secret,
		})
		got, _ := e.finishLogin.Execute(context.Background(), passkey.FinishLoginCommand{
			ChallengeID: begun.ChallengeID, Response: holder.auth.Assert(begun.Options),
		})
		if got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonBadChallenge {
			t.Errorf("result = %+v", got)
		}
	})

	t.Run("unknown and malformed challenges", func(t *testing.T) {
		e := newEnv(t)
		for _, id := range []string{"", "nope", "0198a2b4-7c3d-7e5f-8a1b-2c3d4e5f6a7c"} {
			got, err := e.finishLogin.Execute(context.Background(), passkey.FinishLoginCommand{ChallengeID: id, Response: []byte("{}")})
			if err != nil || got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonBadChallenge {
				t.Errorf("challenge %q = %+v, %v", id, got, err)
			}
		}
	})

	t.Run("a refused ceremony changes nothing but the challenge", func(t *testing.T) {
		e := newEnv(t)
		holder := e.enroll()
		weak := *holder.auth
		weak.SkipUserVerification = true
		before := e.credentials(holder.user)[0].Record()
		sessions := e.store.SessionCount()
		got := login(e, &weak)
		if got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonCeremonyFailed {
			t.Fatalf("result = %+v", got)
		}
		if e.store.SessionCount() != sessions {
			t.Error("a session opened without user verification")
		}
		if after := e.credentials(holder.user)[0].Record(); after.SignCount != before.SignCount || !after.LastUsedAt.Equal(before.LastUsedAt) {
			t.Error("a refused ceremony changed the credential")
		}
	})
}

func TestACounterThatDoesNotGrowIsAnAuditedRefusal(t *testing.T) {
	e := newEnv(t)
	holder := e.enroll()
	if got := e.signIn(holder.auth, "", e.newBinding()); got.Outcome != passkey.OutcomeOK {
		t.Fatalf("first = %+v", got)
	}
	sessions := e.store.SessionCount()

	holder.auth.SignCount = 0 // the counter went back: a copy of the key, or a broken device
	got := e.signIn(holder.auth, "", e.newBinding())
	if got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonCloneSuspected {
		t.Fatalf("result = %+v", got)
	}
	if e.store.SessionCount() != sessions {
		t.Error("a session opened for a key with a counter that went back")
	}
	if c := e.credentials(holder.user)[0]; c.SignCount() != 1 {
		t.Errorf("stored counter = %d: a refused use must not move it", c.SignCount())
	}
	found := false
	for _, ev := range e.store.AuditEvents() {
		if ev.Type == port.AuditPasskeyRefused && ev.Fields["reason"] == "clone_suspected" && ev.UserID == holder.user.ID() {
			found = true
		}
	}
	if !found {
		t.Error("the suspected clone was not audited")
	}
}

func TestSyncedPasskeysSignInRepeatedly(t *testing.T) {
	e := newEnv(t)
	user := e.newUser()
	b := e.newBinding()
	auth := testutil.NewSoftAuthenticator(t, rpID, origin)
	auth.Synced, auth.BackupEligible, auth.BackupState = true, true, true
	if got := e.enrollWith(user, auth, e.ticketFor(user, dpasskey.TicketEnroll, b), b); got.Outcome != passkey.OutcomeOK {
		t.Fatalf("enroll = %+v", got)
	}
	for range 3 {
		if got := e.signIn(auth, "", e.newBinding()); got.Outcome != passkey.OutcomeOK {
			t.Fatalf("sign-in with a zero counter = %+v", got)
		}
	}
	c := e.credentials(user)[0]
	if !c.BackupEligible() || !c.BackupState() || c.SignCount() != 0 {
		t.Errorf("credential = %+v", c.Record())
	}
}

func TestLoginRollsBackWhenTheSessionCannotBeSigned(t *testing.T) {
	signer := &switchSigner{}
	e := newEnvWith(t, nil, func(real port.AccessSigner) port.AccessSigner {
		signer.inner = real
		return signer
	})
	holder := e.enroll()
	signer.fail = true
	sessions, count := e.store.SessionCount(), e.credentials(holder.user)[0].SignCount()

	begun, _ := e.beginLogin.Execute(context.Background(), passkey.BeginLoginCommand{})
	_, err := e.finishLogin.Execute(context.Background(), passkey.FinishLoginCommand{
		ChallengeID: begun.ChallengeID, Response: holder.auth.Assert(begun.Options),
	})
	if err == nil {
		t.Fatal("a signing failure was swallowed")
	}
	if e.store.SessionCount() != sessions || e.credentials(holder.user)[0].SignCount() != count {
		t.Error("a failed sign-in left a session or a moved counter behind")
	}
}

// block bars the user, as an operator does.
func (e *env) block(user *identity.User) {
	e.t.Helper()
	e.do(func(ctx context.Context, st port.Stores) error {
		u, err := st.Users.Get(ctx, user.ID())
		if err != nil {
			return err
		}
		if err := u.Block(e.clock.Now()); err != nil {
			return err
		}
		return st.Users.SetBlocked(ctx, u)
	})
}

func (e *env) refusals(reason string) int {
	e.t.Helper()
	n := 0
	for _, ev := range e.store.AuditEvents() {
		if ev.Type == port.AuditPasskeyRefused && ev.Fields["reason"] == reason {
			n++
		}
	}
	return n
}

func TestABlockedUserCannotSignInWithAKeyOrASecondFactor(t *testing.T) {
	e := newEnv(t)
	holder := e.enroll()
	b := e.newBinding()
	second := e.ticketFor(holder.user, dpasskey.TicketSecondFactor, b)
	sessions := e.store.SessionCount()
	e.block(holder.user)

	alone := e.signIn(holder.auth, "", bindingSecret{})
	if alone.Outcome != passkey.OutcomeDenied || alone.Reason != passkey.ReasonBlocked || alone.Session != nil {
		t.Errorf("a blocked user signed in with a key: %+v", alone)
	}
	withCode := e.signIn(holder.auth, second, b)
	if withCode.Outcome != passkey.OutcomeDenied || withCode.Reason != passkey.ReasonBlocked || withCode.Session != nil {
		t.Errorf("a blocked user signed in with a code and a key: %+v", withCode)
	}
	if e.store.SessionCount() != sessions {
		t.Errorf("%d sessions, want %d: a session was issued", e.store.SessionCount(), sessions)
	}
	if got := e.refusals("blocked"); got != 2 {
		t.Errorf("blocked refusals in the audit log = %d, want 2", got)
	}

	// Unblocked, the same user signs in with the same key.
	e.do(func(ctx context.Context, st port.Stores) error {
		u, err := st.Users.Get(ctx, holder.user.ID())
		if err != nil {
			return err
		}
		if err := u.Unblock(e.clock.Now()); err != nil {
			return err
		}
		return st.Users.SetBlocked(ctx, u)
	})
	if got := e.signIn(holder.auth, "", bindingSecret{}); got.Outcome != passkey.OutcomeOK {
		t.Errorf("after unblock: %+v", got)
	}
}

func TestABlockedUserCannotFinishAnEnrollmentThatWasStarted(t *testing.T) {
	e := newEnv(t)
	user := e.newUser()
	b := e.newBinding()
	auth := testutil.NewSoftAuthenticator(t, rpID, origin)
	ticket := e.ticketFor(user, dpasskey.TicketEnroll, b)
	begun, err := e.beginEnroll.Execute(context.Background(), passkey.BeginEnrollCommand{TicketSecret: ticket, BindingSecret: b.secret})
	must(t, err)
	if begun.Outcome != passkey.OutcomeOK {
		t.Fatalf("begin = %+v", begun)
	}
	e.block(user) // between the two requests
	got, err := e.finishEnroll.Execute(context.Background(), passkey.FinishEnrollCommand{
		TicketSecret: ticket, BindingSecret: b.secret, ChallengeID: begun.ChallengeID, Response: auth.Register(begun.Options),
		CredentialName: "Laptop", DeviceName: "test",
	})
	must(t, err)
	if got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonBlocked || got.Session != nil {
		t.Errorf("finish = %+v", got)
	}
	if len(e.credentials(user)) != 0 || e.store.SessionCount() != 0 || e.unusedCodes(user) != 0 {
		t.Error("a blocked user's enrollment left a key, a session or recovery codes behind")
	}
}
