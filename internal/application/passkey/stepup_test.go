package passkey_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"go.airlance.org/auth/internal/adapter/memory"
	"go.airlance.org/auth/internal/application/passkey"
	"go.airlance.org/auth/internal/application/port"
	appsession "go.airlance.org/auth/internal/application/session"
	dpasskey "go.airlance.org/auth/internal/domain/passkey"
	"go.airlance.org/auth/internal/domain/quota"
	"go.airlance.org/auth/internal/testutil"
)

// stepUp runs the whole step-up ceremony for the operation and returns the ticket secret.
func (e *env) stepUp(actor appsession.Actor, auth *testutil.SoftAuthenticator, op dpasskey.Operation) string {
	e.t.Helper()

	got := e.tryStepUp(actor, auth, op)
	if got.Outcome != passkey.OutcomeOK {
		e.t.Fatalf("step-up for %s refused: %+v", op, got)
	}

	return got.TicketSecret
}

func (e *env) tryStepUp(actor appsession.Actor, auth *testutil.SoftAuthenticator, op dpasskey.Operation) passkey.FinishStepUpResult {
	e.t.Helper()
	begun, err := e.beginStepUp.Execute(context.Background(), passkey.BeginStepUpCommand{Actor: actor, Operation: op})
	must(e.t, err)

	if begun.Outcome != passkey.OutcomeOK {
		return passkey.FinishStepUpResult{Outcome: begun.Outcome, Reason: begun.Reason}
	}

	got, err := e.finishStepUp.Execute(context.Background(), passkey.FinishStepUpCommand{Actor: actor, ChallengeID: begun.ChallengeID, Response: auth.Assert(begun.Options)})
	must(e.t, err)

	return got
}

// secondSession opens another session of the user with their passkey.
func (e *env) secondSession(h enrolled) appsession.Actor {
	e.t.Helper()

	got := e.signIn(h.auth, "", e.newBinding())
	if got.Outcome != passkey.OutcomeOK {
		e.t.Fatalf("second session = %+v", got)
	}

	return appsession.Actor{UserID: h.user.ID(), SessionID: got.Session.ID()}
}

func (e *env) revokeSession(actor appsession.Actor) {
	e.t.Helper()
	e.do(func(ctx context.Context, st port.Stores) error {
		s, err := st.Sessions.GetForUpdate(ctx, actor.SessionID)
		if err != nil {
			return err
		}

		s.Revoke(e.clock.Now())

		return st.Sessions.Save(ctx, s)
	})
}

func (e *env) addKey(actor appsession.Actor, ticket string, auth *testutil.SoftAuthenticator, name string) passkey.FinishAddResult {
	e.t.Helper()
	begun, err := e.beginAdd.Execute(context.Background(), passkey.BeginAddCommand{Actor: actor, StepUpSecret: ticket})
	must(e.t, err)

	if begun.Outcome != passkey.OutcomeOK {
		return passkey.FinishAddResult{Outcome: begun.Outcome, Reason: begun.Reason}
	}

	got, err := e.finishAdd.Execute(context.Background(), passkey.FinishAddCommand{
		Actor: actor, StepUpSecret: ticket, ChallengeID: begun.ChallengeID, Response: auth.Register(begun.Options), Name: name,
	})
	must(e.t, err)

	return got
}

func TestStepUpIsAFreshStrongProofForOneOperationOfOneSession(t *testing.T) {
	e := newEnv(t)
	h := e.enroll()

	begun, err := e.beginStepUp.Execute(context.Background(), passkey.BeginStepUpCommand{Actor: h.actor, Operation: dpasskey.OperationDeletePasskey})
	must(t, err)

	if begun.Outcome != passkey.OutcomeOK || begun.ChallengeID == "" || len(begun.Options) == 0 {
		t.Fatalf("begin = %+v", begun)
	}

	got, err := e.finishStepUp.Execute(context.Background(), passkey.FinishStepUpCommand{Actor: h.actor, ChallengeID: begun.ChallengeID, Response: h.auth.Assert(begun.Options)})
	must(t, err)

	if got.Outcome != passkey.OutcomeOK || got.TicketSecret == "" || got.Operation != dpasskey.OperationDeletePasskey {
		t.Fatalf("finish = %+v", got)
	}

	if want := e.clock.Now().Add(5 * time.Minute); !got.TicketExpiresAt.Equal(want) {
		t.Errorf("ticket expires %v, want %v: the window is five minutes", got.TicketExpiresAt, want)
	}

	if c := e.credentials(h.user)[0]; c.SignCount() != 1 {
		t.Errorf("the step-up did not count as a use of the key: %d", c.SignCount())
	}

	granted := 0

	for _, ev := range e.store.AuditEvents() {
		if ev.Type == port.AuditStepUpGranted && ev.Fields["operation"] == "delete_passkey" && ev.SessionID == h.actor.SessionID {
			granted++
		}

		for _, v := range ev.Fields {
			if strings.Contains(v, got.TicketSecret) {
				t.Error("an audit event carries the ticket secret")
			}
		}
	}

	if granted != 1 {
		t.Errorf("%d grants audited, want 1", granted)
	}
}

func TestStepUpCeremonyRefusals(t *testing.T) {
	t.Run("an unknown operation", func(t *testing.T) {
		e := newEnv(t)

		h := e.enroll()
		for _, op := range []dpasskey.Operation{"", "wipe", "login"} {
			begun, err := e.beginStepUp.Execute(context.Background(), passkey.BeginStepUpCommand{Actor: h.actor, Operation: op})
			must(t, err)

			if begun.Outcome != passkey.OutcomeDenied {
				t.Errorf("operation %q = %+v", op, begun)
			}
		}
	})

	t.Run("a revoked session", func(t *testing.T) {
		e := newEnv(t)
		h := e.enroll()
		e.revokeSession(h.actor)

		got := e.tryStepUp(h.actor, h.auth, dpasskey.OperationDeletePasskey)
		if got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonNoSession {
			t.Errorf("result = %+v", got)
		}
		// Beginning is refused on its own: a revoked session is not given a ceremony to run.
		begun, err := e.beginStepUp.Execute(context.Background(), passkey.BeginStepUpCommand{Actor: h.actor, Operation: dpasskey.OperationDeletePasskey})
		must(t, err)

		if begun.Outcome != passkey.OutcomeDenied || begun.Reason != passkey.ReasonNoSession || begun.ChallengeID != "" {
			t.Errorf("begin = %+v", begun)
		}
	})

	t.Run("a session of someone else", func(t *testing.T) {
		e := newEnv(t)
		a, b := e.enroll(), e.enroll()
		forged := appsession.Actor{UserID: a.user.ID(), SessionID: b.actor.SessionID}

		got := e.tryStepUp(forged, a.auth, dpasskey.OperationDeletePasskey)
		if got.Outcome != passkey.OutcomeDenied {
			t.Errorf("result = %+v", got)
		}
	})

	t.Run("a key of another user", func(t *testing.T) {
		e := newEnv(t)
		victim, intruder := e.enroll(), e.enroll()
		tickets := e.store.TicketCount()

		got := e.tryStepUp(victim.actor, intruder.auth, dpasskey.OperationDeletePasskey)
		if got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonUnknownKey {
			t.Errorf("result = %+v: someone else's key must not prove the signed-in user", got)
		}

		if e.store.TicketCount() != tickets {
			t.Error("a ticket was issued")
		}
	})

	t.Run("a key without user verification", func(t *testing.T) {
		e := newEnv(t)
		h := e.enroll()
		weak := *h.auth

		weak.SkipUserVerification = true
		if got := e.tryStepUp(h.actor, &weak, dpasskey.OperationDeletePasskey); got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonCeremonyFailed {
			t.Errorf("result = %+v", got)
		}
	})

	t.Run("a counter that did not grow", func(t *testing.T) {
		e := newEnv(t)
		h := e.enroll()
		e.stepUp(h.actor, h.auth, dpasskey.OperationDeletePasskey)

		h.auth.SignCount = 0
		if got := e.tryStepUp(h.actor, h.auth, dpasskey.OperationDeletePasskey); got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonCloneSuspected {
			t.Errorf("result = %+v", got)
		}
	})

	t.Run("a challenge of another session of the same user", func(t *testing.T) {
		e := newEnv(t)
		h := e.enroll()
		other := e.secondSession(h)
		begun, _ := e.beginStepUp.Execute(context.Background(), passkey.BeginStepUpCommand{Actor: other, Operation: dpasskey.OperationDeletePasskey})
		got, err := e.finishStepUp.Execute(context.Background(), passkey.FinishStepUpCommand{Actor: h.actor, ChallengeID: begun.ChallengeID, Response: h.auth.Assert(begun.Options)})
		must(t, err)

		if got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonBadChallenge {
			t.Errorf("result = %+v", got)
		}
	})

	t.Run("a login challenge cannot become a step-up", func(t *testing.T) {
		e := newEnv(t)
		h := e.enroll()
		begun, _ := e.beginLogin.Execute(context.Background(), passkey.BeginLoginCommand{})
		got, err := e.finishStepUp.Execute(context.Background(), passkey.FinishStepUpCommand{Actor: h.actor, ChallengeID: begun.ChallengeID, Response: h.auth.Assert(begun.Options)})
		must(t, err)

		if got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonBadChallenge {
			t.Errorf("result = %+v", got)
		}
	})

	t.Run("an expired or replayed challenge", func(t *testing.T) {
		e := newEnv(t)
		h := e.enroll()
		begun, _ := e.beginStepUp.Execute(context.Background(), passkey.BeginStepUpCommand{Actor: h.actor, Operation: dpasskey.OperationDeletePasskey})
		response := h.auth.Assert(begun.Options)

		cmd := passkey.FinishStepUpCommand{Actor: h.actor, ChallengeID: begun.ChallengeID, Response: response}
		if got, _ := e.finishStepUp.Execute(context.Background(), cmd); got.Outcome != passkey.OutcomeOK {
			t.Fatalf("first = %+v", got)
		}

		if got, _ := e.finishStepUp.Execute(context.Background(), cmd); got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonBadChallenge {
			t.Errorf("replay = %+v", got)
		}

		late, _ := e.beginStepUp.Execute(context.Background(), passkey.BeginStepUpCommand{Actor: h.actor, Operation: dpasskey.OperationDeletePasskey})
		response = h.auth.Assert(late.Options)

		e.clock.Advance(dpasskey.ChallengeTTL)

		if got, _ := e.finishStepUp.Execute(context.Background(), passkey.FinishStepUpCommand{Actor: h.actor, ChallengeID: late.ChallengeID, Response: response}); got.Reason != passkey.ReasonBadChallenge {
			t.Errorf("expired = %+v", got)
		}
	})

	t.Run("malformed challenge ids", func(t *testing.T) {
		e := newEnv(t)

		h := e.enroll()
		for _, id := range []string{"", "x", "0198a2b4-7c3d-7e5f-8a1b-2c3d4e5f6a7c"} {
			got, err := e.finishStepUp.Execute(context.Background(), passkey.FinishStepUpCommand{Actor: h.actor, ChallengeID: id, Response: []byte("{}")})
			must(t, err)

			if got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonBadChallenge {
				t.Errorf("challenge %q = %+v", id, got)
			}
		}
	})
}

func TestStepUpTicketIsBoundToItsOperationItsSessionAndItsUser(t *testing.T) {
	e := newEnv(t)
	h := e.enroll()
	other := e.secondSession(h)
	stranger := e.enroll()

	del := func(actor appsession.Actor, ticket, id string) passkey.DeleteResult {
		t.Helper()

		got, err := e.deleteKey.Execute(context.Background(), passkey.DeleteCommand{Actor: actor, StepUpSecret: ticket, ID: id})
		must(t, err)

		return got
	}
	// A second key, so that a delete can succeed.
	e.addKey(h.actor, e.stepUp(h.actor, h.auth, dpasskey.OperationAddPasskey), testutil.NewSoftAuthenticator(t, rpID, origin), "second")
	victim := e.credentials(h.user)[1].ID().String()

	forAdd := e.stepUp(h.actor, h.auth, dpasskey.OperationAddPasskey)
	if got := del(h.actor, forAdd, victim); got.Outcome != passkey.OutcomeStepUpRequired {
		t.Errorf("a ticket for another operation = %+v", got)
	}

	forDelete := e.stepUp(h.actor, h.auth, dpasskey.OperationDeletePasskey)
	if got := del(other, forDelete, victim); got.Outcome != passkey.OutcomeStepUpRequired {
		t.Errorf("a ticket of another session of the same user = %+v", got)
	}

	if got := del(stranger.actor, forDelete, victim); got.Outcome != passkey.OutcomeStepUpRequired {
		t.Errorf("a ticket of another user = %+v", got)
	}

	for _, bad := range []string{"", "x", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"} {
		if got := del(h.actor, bad, victim); got.Outcome != passkey.OutcomeStepUpRequired {
			t.Errorf("ticket %q = %+v", bad, got)
		}
	}

	if len(e.credentials(h.user)) != 2 {
		t.Fatal("a refused delete removed a key")
	}
	// None of the refusals spent the ticket.
	if got := del(h.actor, forDelete, victim); got.Outcome != passkey.OutcomeOK {
		t.Fatalf("the right use = %+v", got)
	}

	if got := del(h.actor, forDelete, e.credentials(h.user)[0].ID().String()); got.Outcome != passkey.OutcomeStepUpRequired {
		t.Errorf("a second use of one ticket = %+v", got)
	}

	// The window is five minutes.
	late := e.stepUp(h.actor, h.auth, dpasskey.OperationRegenerateCodes)
	e.clock.Advance(dpasskey.StepUpTicketTTL)

	if got, _ := e.regenerate.Execute(context.Background(), passkey.RegenerateCommand{Actor: h.actor, StepUpSecret: late}); got.Outcome != passkey.OutcomeStepUpRequired {
		t.Errorf("an expired ticket = %+v", got)
	}
}

func TestAddingAPasskeyNeedsAStepUpAndSpendsIt(t *testing.T) {
	e := newEnv(t)
	h := e.enroll()

	if got := e.addKey(h.actor, "", testutil.NewSoftAuthenticator(t, rpID, origin), "x"); got.Outcome != passkey.OutcomeStepUpRequired {
		t.Fatalf("without a ticket = %+v", got)
	}

	ticket := e.stepUp(h.actor, h.auth, dpasskey.OperationAddPasskey)
	second := testutil.NewSoftAuthenticator(t, rpID, origin)

	got := e.addKey(h.actor, ticket, second, "Phone")
	if got.Outcome != passkey.OutcomeOK || got.Credential.Name != "Phone" || got.Credential.ID == "" {
		t.Fatalf("add = %+v", got)
	}

	creds := e.credentials(h.user)
	if len(creds) != 2 || creds[1].Name() != "Phone" {
		t.Fatalf("credentials = %d", len(creds))
	}
	// The ticket is spent, and adding a key opens no session and touches no code.
	if again := e.addKey(h.actor, ticket, testutil.NewSoftAuthenticator(t, rpID, origin), "x"); again.Outcome != passkey.OutcomeStepUpRequired {
		t.Errorf("a second add with one ticket = %+v", again)
	}

	if e.store.SessionCount() != 1 || e.unusedCodes(h.user) != dpasskey.RecoveryCodeCount {
		t.Errorf("sessions %d, codes %d: adding a key must change neither", e.store.SessionCount(), e.unusedCodes(h.user))
	}
	// The new key signs in.
	if in := e.signIn(second, "", e.newBinding()); in.Outcome != passkey.OutcomeOK || in.User.ID() != h.user.ID() {
		t.Errorf("sign-in with the added key = %+v", in)
	}
	// The same authenticator cannot be registered twice.
	if dup := e.addKey(h.actor, e.stepUp(h.actor, h.auth, dpasskey.OperationAddPasskey), second, "again"); dup.Outcome != passkey.OutcomeDenied {
		t.Errorf("a key added twice = %+v", dup)
	}
}

func TestAddingAPasskeyRefusals(t *testing.T) {
	t.Run("a challenge of another ticket", func(t *testing.T) {
		e := newEnv(t)
		h := e.enroll()
		first := e.stepUp(h.actor, h.auth, dpasskey.OperationAddPasskey)
		second := e.stepUp(h.actor, h.auth, dpasskey.OperationAddPasskey)
		begun, _ := e.beginAdd.Execute(context.Background(), passkey.BeginAddCommand{Actor: h.actor, StepUpSecret: first})
		auth := testutil.NewSoftAuthenticator(t, rpID, origin)
		got, err := e.finishAdd.Execute(context.Background(), passkey.FinishAddCommand{
			Actor: h.actor, StepUpSecret: second, ChallengeID: begun.ChallengeID, Response: auth.Register(begun.Options),
		})
		must(t, err)

		if got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonBadChallenge {
			t.Errorf("result = %+v", got)
		}

		if len(e.credentials(h.user)) != 1 {
			t.Error("a key was added with a challenge of another ticket")
		}
	})

	t.Run("a refused ceremony spends the challenge, not the ticket", func(t *testing.T) {
		e := newEnv(t)
		h := e.enroll()
		ticket := e.stepUp(h.actor, h.auth, dpasskey.OperationAddPasskey)
		weak := testutil.NewSoftAuthenticator(t, rpID, origin)

		weak.SkipUserVerification = true
		if got := e.addKey(h.actor, ticket, weak, "weak"); got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonCeremonyFailed {
			t.Fatalf("result = %+v", got)
		}

		if got := e.addKey(h.actor, ticket, testutil.NewSoftAuthenticator(t, rpID, origin), "ok"); got.Outcome != passkey.OutcomeOK {
			t.Errorf("a fresh ceremony with the same ticket = %+v", got)
		}
	})

	t.Run("the limit of keys", func(t *testing.T) {
		e := newEnv(t)

		h := e.enroll()
		for range dpasskey.MaxPerUser - 1 {
			if got := e.addKey(h.actor, e.stepUp(h.actor, h.auth, dpasskey.OperationAddPasskey), testutil.NewSoftAuthenticator(t, rpID, origin), "k"); got.Outcome != passkey.OutcomeOK {
				t.Fatalf("below the limit = %+v", got)
			}
		}

		got := e.addKey(h.actor, e.stepUp(h.actor, h.auth, dpasskey.OperationAddPasskey), testutil.NewSoftAuthenticator(t, rpID, origin), "k")
		if got.Outcome != passkey.OutcomeConflict || got.Reason != passkey.ReasonTooManyKeys {
			t.Errorf("over the limit = %+v", got)
		}
	})

	t.Run("a bad name", func(t *testing.T) {
		e := newEnv(t)
		h := e.enroll()
		ticket := e.stepUp(h.actor, h.auth, dpasskey.OperationAddPasskey)

		_, err := e.finishAdd.Execute(context.Background(), passkey.FinishAddCommand{
			Actor: h.actor, StepUpSecret: ticket, ChallengeID: "0198a2b4-7c3d-7e5f-8a1b-2c3d4e5f6a7c", Name: strings.Repeat("x", 65),
		})
		if err == nil {
			t.Error("a long name was accepted")
		}
	})
}

func TestDeletingAPasskeyEndsEveryOtherSessionButNotTheOneThatDeleted(t *testing.T) {
	e := newEnv(t)
	h := e.enroll()
	second := testutil.NewSoftAuthenticator(t, rpID, origin)
	e.addKey(h.actor, e.stepUp(h.actor, h.auth, dpasskey.OperationAddPasskey), second, "second")
	// Two other devices are signed in; a different user has a session too.
	phone, laptop := e.secondSession(h), e.secondSession(h)
	stranger := e.enroll()
	creds := e.credentials(h.user)

	got, err := e.deleteKey.Execute(context.Background(), passkey.DeleteCommand{
		Actor: h.actor, StepUpSecret: e.stepUp(h.actor, h.auth, dpasskey.OperationDeletePasskey), ID: creds[0].ID().String(),
	})
	must(t, err)

	if got.Outcome != passkey.OutcomeOK {
		t.Fatalf("delete = %+v", got)
	}

	active := func(actor appsession.Actor) bool {
		sess, ok := e.store.Session(actor.SessionID)
		return ok && sess.Active(e.clock.Now())
	}
	if !active(h.actor) {
		t.Error("the session that deleted the key ended")
	}

	for name, actor := range map[string]appsession.Actor{"phone": phone, "laptop": laptop} {
		if active(actor) {
			t.Errorf("the %s session survived the deletion of a key", name)
		}

		for _, tok := range e.store.TokensOfSession(actor.SessionID) {
			if tok.RevokedAt().IsZero() {
				t.Errorf("the %s session keeps a live refresh token", name)
			}
		}
	}

	if !active(stranger.actor) {
		t.Error("another user's session ended")
	}

	for _, tok := range e.store.TokensOfSession(h.actor.SessionID) {
		if !tok.RevokedAt().IsZero() {
			t.Error("the refresh token of the kept session was revoked")
		}
	}

	events := e.store.AuditEvents()

	last := events[len(events)-1]
	if last.Type != port.AuditAllSessionsRevoked || last.Fields["scope"] != "others" || last.Fields["reason"] != "key_deleted" || last.UserID != h.user.ID() {
		t.Errorf("last audit event = %+v", last)
	}
}

func TestARefusedDeletionEndsNoSession(t *testing.T) {
	e := newEnv(t)
	h := e.enroll()
	other := e.secondSession(h)
	only := e.credentials(h.user)[0].ID().String() // the only key: the deletion is refused

	got, err := e.deleteKey.Execute(context.Background(), passkey.DeleteCommand{
		Actor: h.actor, StepUpSecret: e.stepUp(h.actor, h.auth, dpasskey.OperationDeletePasskey), ID: only,
	})
	must(t, err)

	if got.Outcome != passkey.OutcomeConflict {
		t.Fatalf("delete = %+v", got)
	}

	if sess, _ := e.store.Session(other.SessionID); !sess.Active(e.clock.Now()) {
		t.Error("a refused deletion ended another session")
	}
}

func TestDeletingAPasskeyKeepsAtLeastOne(t *testing.T) {
	e := newEnv(t)
	h := e.enroll()
	second := testutil.NewSoftAuthenticator(t, rpID, origin)
	e.addKey(h.actor, e.stepUp(h.actor, h.auth, dpasskey.OperationAddPasskey), second, "second")
	creds := e.credentials(h.user)
	proving := h.auth // the key that proves the step-up; the first one is about to be deleted
	del := func(id string) passkey.DeleteResult {
		t.Helper()

		got, err := e.deleteKey.Execute(context.Background(), passkey.DeleteCommand{
			Actor: h.actor, StepUpSecret: e.stepUp(h.actor, proving, dpasskey.OperationDeletePasskey), ID: id,
		})
		must(t, err)

		return got
	}

	if got := del(creds[0].ID().String()); got.Outcome != passkey.OutcomeOK {
		t.Fatalf("delete one of two = %+v", got)
	}
	// The deleted key can no longer sign in; the survivor still can.
	if got := e.signIn(h.auth, "", e.newBinding()); got.Outcome != passkey.OutcomeDenied {
		t.Errorf("a deleted key signed in: %+v", got)
	}

	if got := e.signIn(second, "", e.newBinding()); got.Outcome != passkey.OutcomeOK {
		t.Errorf("the surviving key = %+v", got)
	}

	proving = second

	last := e.credentials(h.user)
	if len(last) != 1 || last[0].ID() != creds[1].ID() {
		t.Fatalf("keys left = %d", len(last))
	}

	if got := del(last[0].ID().String()); got.Outcome != passkey.OutcomeConflict || got.Reason != passkey.ReasonLastKey {
		t.Errorf("deleting the last key = %+v", got)
	}

	if len(e.credentials(h.user)) != 1 {
		t.Error("the last key was deleted")
	}

	for _, id := range []string{"x", "", "0198a2b4-7c3d-7e5f-8a1b-2c3d4e5f6a7c"} {
		if got := del(id); got.Outcome != passkey.OutcomeNotFound {
			t.Errorf("id %q = %+v", id, got)
		}
	}
	// Another user's key looks like a missing one and is not touched.
	other := e.enroll()
	e.addKey(other.actor, e.stepUp(other.actor, other.auth, dpasskey.OperationAddPasskey), testutil.NewSoftAuthenticator(t, rpID, origin), "second")

	foreign := e.credentials(other.user)[0].ID().String()
	if got := del(foreign); got.Outcome != passkey.OutcomeNotFound {
		t.Errorf("another user's key = %+v", got)
	}

	if len(e.credentials(other.user)) != 2 {
		t.Error("another user's key was deleted")
	}
	// A refusal that changed nothing leaves the ticket for a better try.
	ticket := e.stepUp(h.actor, second, dpasskey.OperationDeletePasskey)
	for range 2 {
		if got, _ := e.deleteKey.Execute(context.Background(), passkey.DeleteCommand{Actor: h.actor, StepUpSecret: ticket, ID: last[0].ID().String()}); got.Outcome != passkey.OutcomeConflict {
			t.Fatalf("the last key = %+v", got)
		}
	}
}

func TestRegeneratingRecoveryCodesReplacesTheWholeSet(t *testing.T) {
	e := newEnv(t)

	h := e.enroll()
	if got, _ := e.regenerate.Execute(context.Background(), passkey.RegenerateCommand{Actor: h.actor}); got.Outcome != passkey.OutcomeStepUpRequired {
		t.Fatalf("without a ticket = %+v", got)
	}

	ticket := e.stepUp(h.actor, h.auth, dpasskey.OperationRegenerateCodes)
	got, err := e.regenerate.Execute(context.Background(), passkey.RegenerateCommand{Actor: h.actor, StepUpSecret: ticket})
	must(t, err)

	if got.Outcome != passkey.OutcomeOK || len(got.Codes) != dpasskey.RecoveryCodeCount || e.unusedCodes(h.user) != dpasskey.RecoveryCodeCount {
		t.Fatalf("regenerate = %+v, stored %d", got, e.unusedCodes(h.user))
	}

	for _, old := range h.codes {
		if slices.Contains(got.Codes, old) {
			t.Fatalf("code %s survived the regeneration", old)
		}
	}
	// An old code no longer buys a recovery; a new one does.
	b := e.newBinding()
	if r := e.redeem(e.ticketFor(h.user, dpasskey.TicketSecondFactor, b), b, h.codes[0]); r.Outcome != passkey.OutcomeDenied {
		t.Errorf("an old code = %+v", r)
	}

	b2 := e.newBinding()
	if r := e.redeem(e.ticketFor(h.user, dpasskey.TicketSecondFactor, b2), b2, got.Codes[0]); r.Outcome != passkey.OutcomeOK {
		t.Errorf("a new code = %+v", r)
	}
	// The ticket was spent.
	if again, _ := e.regenerate.Execute(context.Background(), passkey.RegenerateCommand{Actor: h.actor, StepUpSecret: ticket}); again.Outcome != passkey.OutcomeStepUpRequired {
		t.Errorf("a second regeneration with one ticket = %+v", again)
	}
}

func TestListingAndRenamingPasskeys(t *testing.T) {
	e := newEnv(t)
	h := e.enroll()
	e.addKey(h.actor, e.stepUp(h.actor, h.auth, dpasskey.OperationAddPasskey), testutil.NewSoftAuthenticator(t, rpID, origin), "Phone")

	listed, err := e.list.Execute(context.Background(), h.actor)
	must(t, err)

	if listed.Outcome != passkey.OutcomeOK || len(listed.Credentials) != 2 || listed.Credentials[0].Name != "Laptop" || listed.Credentials[1].Name != "Phone" {
		t.Fatalf("list = %+v", listed)
	}

	if listed.Credentials[0].LastUsedAt.IsZero() {
		t.Error("the key used for the step-up shows no last use")
	}
	// Renaming needs no step-up.
	id := listed.Credentials[1].ID
	renamed, err := e.rename.Execute(context.Background(), passkey.RenameCommand{Actor: h.actor, ID: id, Name: "  Work phone "})
	must(t, err)

	if renamed.Outcome != passkey.OutcomeOK || renamed.Credential.Name != "Work phone" {
		t.Errorf("rename = %+v", renamed)
	}
	// Another user's key and a missing one look alike, and a bad label is a refusal before anything happens.
	stranger := e.enroll()
	for _, id := range []string{id, "x", "0198a2b4-7c3d-7e5f-8a1b-2c3d4e5f6a7c"} {
		got, err := e.rename.Execute(context.Background(), passkey.RenameCommand{Actor: stranger.actor, ID: id, Name: "mine now"})
		must(t, err)

		if got.Outcome != passkey.OutcomeNotFound {
			t.Errorf("rename %q by a stranger = %+v", id, got)
		}
	}

	if _, err := e.rename.Execute(context.Background(), passkey.RenameCommand{Actor: h.actor, ID: id, Name: " "}); err == nil {
		t.Error("a blank label was accepted")
	}
	// A revoked session sees and changes nothing.
	e.revokeSession(h.actor)

	if got, _ := e.list.Execute(context.Background(), h.actor); got.Outcome != passkey.OutcomeDenied || len(got.Credentials) != 0 {
		t.Errorf("list after revoke = %+v", got)
	}
}

func TestStepUpAndAddingAreRateLimitedPerSession(t *testing.T) {
	profile, err := quota.NewProfile(map[quota.Scope][]quota.Window{quota.PasskeyRef: {{Limit: 2, Per: time.Hour}}})
	if err != nil {
		t.Fatal(err)
	}

	e := newEnvWith(t, nil, nil, memory.WithQuota(profile))

	h := e.enroll()
	for range 2 {
		if got, _ := e.beginStepUp.Execute(context.Background(), passkey.BeginStepUpCommand{Actor: h.actor, Operation: dpasskey.OperationDeletePasskey}); got.Outcome != passkey.OutcomeOK {
			t.Fatalf("within the budget = %+v", got)
		}
	}

	if got, _ := e.beginStepUp.Execute(context.Background(), passkey.BeginStepUpCommand{Actor: h.actor, Operation: dpasskey.OperationDeletePasskey}); got.Outcome != passkey.OutcomeRateLimited {
		t.Errorf("over the budget = %+v", got)
	}
	// Another session has its own.
	if got, _ := e.beginStepUp.Execute(context.Background(), passkey.BeginStepUpCommand{Actor: e.secondSession(h), Operation: dpasskey.OperationDeletePasskey}); got.Outcome != passkey.OutcomeOK {
		t.Errorf("another session = %+v", got)
	}
}

func TestSensitiveOperationsRollBackWhenTheirAuditFails(t *testing.T) {
	e := newEnv(t)
	h := e.enroll()
	e.addKey(h.actor, e.stepUp(h.actor, h.auth, dpasskey.OperationAddPasskey), testutil.NewSoftAuthenticator(t, rpID, origin), "second")
	victim := e.credentials(h.user)[1].ID().String()
	ticket := e.stepUp(h.actor, h.auth, dpasskey.OperationDeletePasskey)

	e.faults.wrap = func(s port.Stores) port.Stores { s.Audit = failingAudit{}; return s }
	_, err := e.deleteKey.Execute(context.Background(), passkey.DeleteCommand{Actor: h.actor, StepUpSecret: ticket, ID: victim})
	e.faults.wrap = nil

	if err == nil {
		t.Fatal("an audit failure was swallowed")
	}

	if len(e.credentials(h.user)) != 2 {
		t.Error("the key was deleted although the transaction failed")
	}

	if got, _ := e.deleteKey.Execute(context.Background(), passkey.DeleteCommand{Actor: h.actor, StepUpSecret: ticket, ID: victim}); got.Outcome != passkey.OutcomeOK {
		t.Errorf("retry with the same ticket = %+v: a failed delete must not spend it", got)
	}
}

type failingAudit struct{}

func (failingAudit) Record(context.Context, port.AuditEvent) error {
	return errBoom
}
