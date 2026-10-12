package passkey_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"airlance.org/auth/internal/application/passkey"
	"airlance.org/auth/internal/application/port"
	dpasskey "airlance.org/auth/internal/domain/passkey"
	"airlance.org/auth/internal/testutil"
)

func TestFirstEnrollmentOpensASessionAndHandsOutRecoveryCodes(t *testing.T) {
	e := newEnv(t)
	user := e.newUser()
	b := e.newBinding()
	auth := testutil.NewSoftAuthenticator(t, rpID, origin)
	ticket := e.ticketFor(user, dpasskey.TicketEnroll, b)

	got := e.enrollWith(user, auth, ticket, b)
	if got.Outcome != passkey.OutcomeOK {
		t.Fatalf("result = %+v", got)
	}

	if got.Session == nil || got.User.ID() != user.ID() || got.RefreshSecret == "" || got.Access.Value == "" {
		t.Fatalf("no session: %+v", got.SignedIn)
	}
	if want := []string{"otp", "passkey"}; !slices.Equal(got.Session.AMR(), want) {
		t.Errorf("amr = %v, want %v", got.Session.AMR(), want)
	}
	claims, err := e.verify.VerifyAccess(got.Access.Value)
	if err != nil || claims.UserID != user.ID() || claims.SessionID != got.Session.ID() || !slices.Equal(claims.AMR, []string{"otp", "passkey"}) {
		t.Errorf("access claims = %+v, %v", claims, err)
	}
	if got.Session.Binding() != b.hash {
		t.Error("the session must carry the binding of the email proof")
	}
	if got.Session.DeviceName() != "test" {
		t.Errorf("device name = %q", got.Session.DeviceName())
	}

	creds := e.credentials(user)
	if len(creds) != 1 || creds[0].Name() != "Laptop" || creds[0].ID() != got.CredentialID {
		t.Fatalf("credentials = %+v", creds)
	}

	if len(got.RecoveryCodes) != dpasskey.RecoveryCodeCount || e.unusedCodes(user) != dpasskey.RecoveryCodeCount {
		t.Fatalf("%d codes shown, %d stored", len(got.RecoveryCodes), e.unusedCodes(user))
	}
	seen := map[string]bool{}
	for _, code := range got.RecoveryCodes {
		normalized, ok := dpasskey.NormalizeRecoveryCode(code)
		if !ok || strings.Count(code, "-") != 3 || seen[normalized] {
			t.Errorf("recovery code %q is malformed or repeated", code)
		}
		seen[normalized] = true
	}

	types := map[port.AuditType]bool{}
	for _, ev := range e.store.AuditEvents() {
		types[ev.Type] = true
		for _, v := range ev.Fields {
			if strings.Contains(v, ticket) || strings.Contains(v, b.secret) {
				t.Errorf("audit event %s carries a secret", ev.Type)
			}
		}
	}
	if !types[port.AuditLoginSucceeded] || !types[port.AuditPasskeyEnrolled] {
		t.Errorf("audit events = %v", types)
	}
}

func TestEnrollmentTicketIsSingleUse(t *testing.T) {
	e := newEnv(t)
	user := e.newUser()
	b := e.newBinding()
	ticket := e.ticketFor(user, dpasskey.TicketEnroll, b)

	if first := e.enrollWith(user, testutil.NewSoftAuthenticator(t, rpID, origin), ticket, b); first.Outcome != passkey.OutcomeOK {
		t.Fatalf("first = %+v", first)
	}
	again := e.enrollWith(user, testutil.NewSoftAuthenticator(t, rpID, origin), ticket, b)
	if again.Outcome != passkey.OutcomeDenied || again.Reason != passkey.ReasonBadTicket {
		t.Errorf("second use = %+v, want a bad ticket", again)
	}
	if n := len(e.credentials(user)); n != 1 {
		t.Errorf("%d credentials, want 1", n)
	}
	if e.store.SessionCount() != 1 {
		t.Errorf("%d sessions, want 1", e.store.SessionCount())
	}
}

func TestEnrollmentRefusals(t *testing.T) {
	t.Run("a ticket with another client's binding", func(t *testing.T) {
		e := newEnv(t)
		user := e.newUser()
		ticket := e.ticketFor(user, dpasskey.TicketEnroll, e.newBinding())
		got := e.enrollWith(user, testutil.NewSoftAuthenticator(t, rpID, origin), ticket, e.newBinding())
		if got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonBadTicket {
			t.Errorf("result = %+v", got)
		}
	})

	t.Run("a malformed binding or ticket", func(t *testing.T) {
		e := newEnv(t)
		user := e.newUser()
		b := e.newBinding()
		ticket := e.ticketFor(user, dpasskey.TicketEnroll, b)
		got, err := e.beginEnroll.Execute(context.Background(), passkey.BeginEnrollCommand{TicketSecret: ticket, BindingSecret: "short"})
		if err != nil || got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonBadBinding {
			t.Errorf("bad binding = %+v, %v", got, err)
		}
		got, err = e.beginEnroll.Execute(context.Background(), passkey.BeginEnrollCommand{TicketSecret: "nope", BindingSecret: b.secret})
		if err != nil || got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonBadTicket {
			t.Errorf("bad ticket = %+v, %v", got, err)
		}
		unknown, _, _ := e.tickets.NewTicketSecret()
		got, err = e.beginEnroll.Execute(context.Background(), passkey.BeginEnrollCommand{TicketSecret: unknown, BindingSecret: b.secret})
		if err != nil || got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonBadTicket {
			t.Errorf("unknown ticket = %+v, %v", got, err)
		}
	})

	t.Run("an expired ticket", func(t *testing.T) {
		e := newEnv(t)
		user := e.newUser()
		b := e.newBinding()
		ticket := e.ticketFor(user, dpasskey.TicketEnroll, b)
		e.clock.Advance(dpasskey.EnrollTicketTTL)
		got := e.enrollWith(user, testutil.NewSoftAuthenticator(t, rpID, origin), ticket, b)
		if got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonBadTicket {
			t.Errorf("result = %+v", got)
		}
	})

	t.Run("tickets of other kinds cannot enroll", func(t *testing.T) {
		for _, kind := range []dpasskey.TicketKind{dpasskey.TicketSecondFactor} {
			e := newEnv(t)
			user := e.newUser()
			b := e.newBinding()
			got := e.enrollWith(user, testutil.NewSoftAuthenticator(t, rpID, origin), e.ticketFor(user, kind, b), b)
			if got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonBadTicket {
				t.Errorf("%s ticket: %+v", kind, got)
			}
			if len(e.credentials(user)) != 0 || e.store.SessionCount() != 0 {
				t.Errorf("%s ticket changed something", kind)
			}
		}
	})

	t.Run("a stale enroll ticket once the user has a key", func(t *testing.T) {
		e := newEnv(t)
		holder := e.enroll()
		b := e.newBinding()
		stale := e.ticketFor(holder.user, dpasskey.TicketEnroll, b)
		got := e.enrollWith(holder.user, testutil.NewSoftAuthenticator(t, rpID, origin), stale, b)
		if got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonAlreadyEnrolled {
			t.Errorf("result = %+v", got)
		}
		if len(e.credentials(holder.user)) != 1 {
			t.Error("a stale ticket added a key to an account that already has one")
		}
	})

	t.Run("a key that belongs to another user changes nothing", func(t *testing.T) {
		e := newEnv(t)
		holder := e.enroll()
		victim := e.enroll()
		// The victim recovers, but offers an authenticator that is registered to someone else.
		b := e.newBinding()
		got := e.enrollWith(victim.user, holder.auth, e.ticketFor(victim.user, dpasskey.TicketRecoveryEnroll, b), b)
		if got.Outcome != passkey.OutcomeDenied {
			t.Errorf("result = %+v, want a refusal", got)
		}
		// A refusal commits what it protects; the old keys of the victim are not part of that.
		if len(e.credentials(victim.user)) != 1 || len(e.credentials(holder.user)) != 1 {
			t.Error("a refused recovery changed the keys")
		}
		if r := e.signIn(victim.auth, "", e.newBinding()); r.Outcome != passkey.OutcomeOK {
			t.Errorf("the victim's own key no longer signs in: %+v", r)
		}
	})

	t.Run("recovery has no limit on old keys because it replaces them", func(t *testing.T) {
		e := newEnv(t)
		holder := e.enroll()
		// Fill the account with keys through recovery tickets, which replace: it never holds more than one.
		for range dpasskey.MaxPerUser + 1 {
			b := e.newBinding()
			got := e.enrollWith(holder.user, testutil.NewSoftAuthenticator(t, rpID, origin), e.ticketFor(holder.user, dpasskey.TicketRecoveryEnroll, b), b)
			if got.Outcome != passkey.OutcomeOK {
				t.Fatalf("recovery = %+v", got)
			}
		}
		if n := len(e.credentials(holder.user)); n != 1 {
			t.Errorf("%d keys after repeated recoveries, want only the last one", n)
		}
	})
}

func TestEnrollmentChallenges(t *testing.T) {
	finish := func(e *env, ticket string, b bindingSecret, challengeID string, response []byte) passkey.FinishEnrollResult {
		t.Helper()
		got, err := e.finishEnroll.Execute(context.Background(), passkey.FinishEnrollCommand{
			TicketSecret: ticket, BindingSecret: b.secret, ChallengeID: challengeID, Response: response,
		})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	t.Run("a challenge of another ticket cannot be finished with mine", func(t *testing.T) {
		e := newEnv(t)
		alice, bob := e.newUser(), e.newUser()
		ab, bb := e.newBinding(), e.newBinding()
		aliceTicket := e.ticketFor(alice, dpasskey.TicketEnroll, ab)
		bobTicket := e.ticketFor(bob, dpasskey.TicketEnroll, bb)
		auth := testutil.NewSoftAuthenticator(t, rpID, origin)

		begun, err := e.beginEnroll.Execute(context.Background(), passkey.BeginEnrollCommand{TicketSecret: aliceTicket, BindingSecret: ab.secret})
		if err != nil || begun.Outcome != passkey.OutcomeOK {
			t.Fatalf("begin = %+v, %v", begun, err)
		}
		got := finish(e, bobTicket, bb, begun.ChallengeID, auth.Register(begun.Options))
		if got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonBadChallenge {
			t.Errorf("result = %+v", got)
		}
		if len(e.credentials(alice))+len(e.credentials(bob)) != 0 || e.store.SessionCount() != 0 {
			t.Error("a foreign challenge registered a key or opened a session")
		}
	})

	t.Run("an unknown or malformed challenge", func(t *testing.T) {
		e := newEnv(t)
		user := e.newUser()
		b := e.newBinding()
		ticket := e.ticketFor(user, dpasskey.TicketEnroll, b)
		for _, id := range []string{"", "x", "0198a2b4-7c3d-7e5f-8a1b-2c3d4e5f6a7c"} {
			if got := finish(e, ticket, b, id, []byte("{}")); got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonBadChallenge {
				t.Errorf("challenge %q = %+v", id, got)
			}
		}
	})

	t.Run("an expired challenge", func(t *testing.T) {
		e := newEnv(t)
		user := e.newUser()
		b := e.newBinding()
		ticket := e.ticketFor(user, dpasskey.TicketEnroll, b)
		auth := testutil.NewSoftAuthenticator(t, rpID, origin)
		begun, _ := e.beginEnroll.Execute(context.Background(), passkey.BeginEnrollCommand{TicketSecret: ticket, BindingSecret: b.secret})
		e.clock.Advance(dpasskey.ChallengeTTL)
		got := finish(e, ticket, b, begun.ChallengeID, auth.Register(begun.Options))
		if got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonBadChallenge {
			t.Errorf("result = %+v", got)
		}
	})

	t.Run("a refused ceremony spends the challenge but not the ticket", func(t *testing.T) {
		e := newEnv(t)
		user := e.newUser()
		b := e.newBinding()
		ticket := e.ticketFor(user, dpasskey.TicketEnroll, b)

		weak := testutil.NewSoftAuthenticator(t, rpID, origin)
		weak.SkipUserVerification = true
		begun, _ := e.beginEnroll.Execute(context.Background(), passkey.BeginEnrollCommand{TicketSecret: ticket, BindingSecret: b.secret})
		response := weak.Register(begun.Options)
		got := finish(e, ticket, b, begun.ChallengeID, response)
		if got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonCeremonyFailed {
			t.Fatalf("result = %+v", got)
		}
		if len(e.credentials(user)) != 0 || e.store.SessionCount() != 0 {
			t.Error("a refused ceremony registered a key or opened a session")
		}
		// The challenge is spent: the same ceremony cannot be tried again.
		strong := testutil.NewSoftAuthenticator(t, rpID, origin)
		if again := finish(e, ticket, b, begun.ChallengeID, strong.Register(begun.Options)); again.Reason != passkey.ReasonBadChallenge {
			t.Errorf("retry on the same challenge = %+v, want a spent challenge", again)
		}
		// The ticket is not: a fresh ceremony works.
		if ok := e.enrollWith(user, strong, ticket, b); ok.Outcome != passkey.OutcomeOK {
			t.Errorf("fresh ceremony with the same ticket = %+v", ok)
		}
		refused := 0
		for _, ev := range e.store.AuditEvents() {
			if ev.Type == port.AuditPasskeyRefused && ev.Fields["reason"] == "ceremony_failed" {
				refused++
			}
		}
		if refused != 1 {
			t.Errorf("%d refusals audited, want 1", refused)
		}
	})
}

func TestEnrollmentRollsBackWhenTheSessionCannotBeSigned(t *testing.T) {
	e := newEnvWith(t, nil, func(port.AccessSigner) port.AccessSigner { return failingSigner{} })
	user := e.newUser()
	b := e.newBinding()
	ticket := e.ticketFor(user, dpasskey.TicketEnroll, b)
	auth := testutil.NewSoftAuthenticator(t, rpID, origin)

	begun, _ := e.beginEnroll.Execute(context.Background(), passkey.BeginEnrollCommand{TicketSecret: ticket, BindingSecret: b.secret})
	_, err := e.finishEnroll.Execute(context.Background(), passkey.FinishEnrollCommand{
		TicketSecret: ticket, BindingSecret: b.secret, ChallengeID: begun.ChallengeID, Response: auth.Register(begun.Options),
	})
	if !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want the signer's error", err)
	}
	if len(e.credentials(user)) != 0 || e.unusedCodes(user) != 0 || e.store.SessionCount() != 0 {
		t.Error("a failed enrollment left a key, recovery codes or a session behind")
	}
	// Nothing was spent: the ticket and the challenge still work once the fault is gone.
	e.do(func(ctx context.Context, st port.Stores) error {
		hash, _ := e.tickets.HashTicketSecret(ticket)
		tk, err := st.Tickets.GetByHashForUpdate(ctx, hash)
		if err != nil || !tk.ConsumedAt().IsZero() {
			t.Errorf("ticket after rollback: %v, consumed %v", err, tk.ConsumedAt())
		}
		return nil
	})
}

func TestEnrollmentRejectsUnstorableNames(t *testing.T) {
	e := newEnv(t)
	user := e.newUser()
	b := e.newBinding()
	ticket := e.ticketFor(user, dpasskey.TicketEnroll, b)
	for name, cmd := range map[string]passkey.FinishEnrollCommand{
		"long credential name": {CredentialName: strings.Repeat("x", dpasskey.MaxNameLength+1)},
		"control in name":      {CredentialName: "a\x00b"},
		"long device name":     {DeviceName: strings.Repeat("x", 200)},
	} {
		cmd.TicketSecret, cmd.BindingSecret, cmd.ChallengeID = ticket, b.secret, "0198a2b4-7c3d-7e5f-8a1b-2c3d4e5f6a7c"
		if _, err := e.finishEnroll.Execute(context.Background(), cmd); !errors.Is(err, passkey.ErrInvalidName) {
			t.Errorf("%s: err = %v, want ErrInvalidName", name, err)
		}
	}
}

func TestBeginEnrollWritesOneChallengeBoundToTheTicket(t *testing.T) {
	e := newEnv(t)
	user := e.newUser()
	b := e.newBinding()
	ticket := e.ticketFor(user, dpasskey.TicketEnroll, b)
	begun, err := e.beginEnroll.Execute(context.Background(), passkey.BeginEnrollCommand{TicketSecret: ticket, BindingSecret: b.secret})
	if err != nil || begun.Outcome != passkey.OutcomeOK || len(begun.Options) == 0 {
		t.Fatalf("begin = %+v, %v", begun, err)
	}
	id, _ := dpasskey.ParseID(begun.ChallengeID)
	e.do(func(ctx context.Context, st port.Stores) error {
		c, err := st.Challenges.GetForUpdate(ctx, id)
		if err != nil || c.Purpose() != dpasskey.ChallengeRegistration || c.UserID() != user.ID() || c.TicketID().IsZero() {
			t.Errorf("challenge = %+v, %v", c, err)
		}
		if want := e.clock.Now().Add(dpasskey.ChallengeTTL); !c.ExpiresAt().Equal(want) {
			t.Errorf("expires %v, want %v", c.ExpiresAt(), want)
		}
		return nil
	})
	// Beginning does not spend the ticket.
	if again, _ := e.beginEnroll.Execute(context.Background(), passkey.BeginEnrollCommand{TicketSecret: ticket, BindingSecret: b.secret}); again.Outcome != passkey.OutcomeOK {
		t.Errorf("second begin = %+v", again)
	}
}

// Finish checks the ticket kind itself: a challenge made for another ticket must not turn a
// second-factor ticket into a registration, even if one reached the store some other way.
func TestFinishEnrollRefusesATicketOfAnotherKindEvenWithAMatchingChallenge(t *testing.T) {
	e := newEnv(t)
	user := e.newUser()
	b := e.newBinding()
	ticket := e.ticketFor(user, dpasskey.TicketSecondFactor, b)
	hash, _ := e.tickets.HashTicketSecret(ticket)
	var ticketID dpasskey.ID
	e.do(func(ctx context.Context, st port.Stores) error {
		tk, err := st.Tickets.GetByHashForUpdate(ctx, hash)
		ticketID = tk.ID()
		return err
	})

	auth := testutil.NewSoftAuthenticator(t, rpID, origin)
	service, _ := apasskeyService()
	subject := port.Subject{ID: user.ID(), Email: user.Email()}
	ceremony, err := service.BeginRegistration(subject)
	must(t, err)
	id, _ := e.factory.IDs.NewPasskeyID()
	challenge, err := dpasskey.NewChallenge(dpasskey.NewChallengeParams{
		ID: id, Purpose: dpasskey.ChallengeRegistration, UserID: user.ID(), TicketID: ticketID, Data: ceremony.State, Now: e.clock.Now(),
	})
	must(t, err)
	e.do(func(ctx context.Context, st port.Stores) error { return st.Challenges.Create(ctx, challenge) })

	got, err := e.finishEnroll.Execute(context.Background(), passkey.FinishEnrollCommand{
		TicketSecret: ticket, BindingSecret: b.secret, ChallengeID: id.String(), Response: auth.Register(ceremony.Options),
	})
	must(t, err)
	if got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonBadTicket {
		t.Errorf("result = %+v", got)
	}
	if len(e.credentials(user)) != 0 || e.store.SessionCount() != 0 {
		t.Error("a second-factor ticket registered a key or opened a session")
	}
}
