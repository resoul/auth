package http_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/identity"
	httpapi "airlance.org/auth/internal/transport/http"
)

func newInviteEnv(t *testing.T, rec *recorder) *env {
	t.Helper()
	e, err := buildEnvMode(t, identity.RegistrationInviteOnly, func(d *httpapi.Deps) {
		if rec != nil {
			d.Requests = rec
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *env) invite(raw string) {
	e.t.Helper()
	email := mustEmail(e.t, raw)
	inv, err := identity.NewInvitation(email, e.clock.Now(), 24*time.Hour)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.store.Do(context.Background(), func(ctx context.Context, s port.Stores) error { return s.Invitations.Save(ctx, inv) }); err != nil {
		e.t.Fatal(err)
	}
}

func TestAnUninvitedStartIsAnOrdinaryStartToTheClientInBothProfiles(t *testing.T) {
	rec := &recorder{}
	e := newInviteEnv(t, rec)
	e.invite("invited@example.test")

	invited := e.start("invited@example.test", "")
	stranger := e.start("stranger@example.test", "")

	if stranger.FlowID == "" || stranger.ClientBinding == "" || !stranger.ExpiresAt.Equal(invited.ExpiresAt) || !stranger.ResendAfter.Equal(invited.ResendAfter) {
		t.Errorf("invited = %+v, stranger = %+v", invited, stranger)
	}
	if len(e.store.OutboxJobs()) != 1 {
		t.Errorf("%d mails queued, want only the invited one", len(e.store.OutboxJobs()))
	}
	// The operator sees what the client cannot.
	if rec.denials("start", "not_invited") != 1 {
		t.Errorf("not_invited refusals = %d (all: %+v)", rec.denials("start", "not_invited"), rec.denied)
	}

	b := newBrowser(e)
	for _, email := range []string{"invited@example.test", "stranger-browser@example.test"} {
		resp := b.send(b.request(http.MethodPost, browserStart, `{"email":"`+email+`"}`))
		if resp.Code != http.StatusAccepted {
			t.Fatalf("browser start of %s = %d %s", email, resp.Code, resp.Body)
		}
	}
	if len(e.store.OutboxJobs()) != 2 {
		t.Errorf("%d mails queued after the browser starts, want 2", len(e.store.OutboxJobs()))
	}
}

func TestAnInvitedAddressRegistersThroughThePasskeyStepAndThenSignsInWithoutTheInvitation(t *testing.T) {
	e := newInviteEnv(t, nil)
	e.invite("invited@example.test")

	first, _ := e.signIn("invited@example.test")
	if first.AccessToken == "" {
		t.Fatal("the invited address did not get a session")
	}
	if _, ok := e.store.User(mustEmail(t, "invited@example.test")); !ok {
		t.Fatal("no account")
	}
	second, _ := e.signIn("invited@example.test")
	if second.User.ID != first.User.ID {
		t.Error("the second sign-in opened another account")
	}
}

func TestAStrangerWhoGuessesNoCodeGetsNothingEvenWithTheRightAnswerToTheirOwnFlow(t *testing.T) {
	e := newInviteEnv(t, nil)
	started := e.start("stranger@example.test", "")
	// No mail was sent, but the code of the flow is derivable on the server: a registration must still be refused.
	rec := e.verify(started.FlowID, e.code(started.FlowID), started.ClientBinding)
	wantProblem(t, rec, http.StatusBadRequest, "invalid_code")
	if _, ok := e.store.User(mustEmail(t, "stranger@example.test")); ok {
		t.Error("an account was created for an address that was never invited")
	}
}
