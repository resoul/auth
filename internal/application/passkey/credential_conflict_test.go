package passkey_test

import (
	"context"
	"testing"

	"go.airlance.org/auth/internal/application/passkey"
	dpasskey "go.airlance.org/auth/internal/domain/passkey"
	"go.airlance.org/auth/internal/testutil"
)

// An authenticator registered to one user is refused for another: a plain refusal, which spends the challenge and
// leaves the ticket usable, not a failed request. These scenarios run on the in-memory store here and on PostgreSQL
// in postgres_integration_test.go, where a unique violation would abort the transaction of the refusal.

func TestAnotherUsersAuthenticatorIsRefusedAtEnrollment(t *testing.T) {
	anotherUsersAuthenticatorIsRefusedAtEnrollment(t, newEnv(t))
}

func TestAnotherUsersAuthenticatorIsRefusedWhenAdded(t *testing.T) {
	anotherUsersAuthenticatorIsRefusedWhenAdded(t, newEnv(t))
}

func anotherUsersAuthenticatorIsRefusedAtEnrollment(t *testing.T, e *env) {
	alice := e.enroll()
	bob := e.newUser()
	b := e.newBinding()
	ticket := e.ticketFor(bob, dpasskey.TicketEnroll, b)

	begun, err := e.beginEnroll.Execute(context.Background(), passkey.BeginEnrollCommand{TicketSecret: ticket, BindingSecret: b.secret})
	must(t, err)

	if begun.Outcome != passkey.OutcomeOK {
		t.Fatalf("begin = %+v", begun)
	}

	finish := func(response []byte) passkey.FinishEnrollResult {
		t.Helper()

		got, err := e.finishEnroll.Execute(context.Background(), passkey.FinishEnrollCommand{
			TicketSecret: ticket, BindingSecret: b.secret, ChallengeID: begun.ChallengeID, Response: response,
			CredentialName: "Laptop", DeviceName: "test",
		})
		must(t, err)

		return got
	}

	// Alice's authenticator answers Bob's ceremony. A copy registers, so that the original keeps Alice's user handle.
	same := *alice.auth
	if got := finish(same.Register(begun.Options)); got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonCeremonyFailed {
		t.Fatalf("enrollment with another user's authenticator = %+v, want denied as a failed ceremony", got)
	}

	// The refusal committed: the challenge is spent.
	if got := finish(testutil.NewSoftAuthenticator(t, rpID, origin).Register(begun.Options)); got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonBadChallenge {
		t.Errorf("the refused ceremony again = %+v, want its challenge spent", got)
	}

	// The ticket is still Bob's to use, with his own authenticator.
	if got := e.enrollWith(bob, testutil.NewSoftAuthenticator(t, rpID, origin), ticket, b); got.Outcome != passkey.OutcomeOK {
		t.Errorf("enrollment with Bob's own authenticator = %+v", got)
	}

	if n := len(e.credentials(bob)); n != 1 {
		t.Errorf("Bob has %d keys, want his own one", n)
	}

	if r := e.signIn(alice.auth, "", e.newBinding()); r.Outcome != passkey.OutcomeOK || r.Session.UserID() != alice.user.ID() {
		t.Errorf("Alice's key after the refusal = %+v", r)
	}
}

func anotherUsersAuthenticatorIsRefusedWhenAdded(t *testing.T, e *env) {
	alice, bob := e.enroll(), e.enroll()
	ticket := e.stepUp(alice.actor, alice.auth, dpasskey.OperationAddPasskey)

	// A copy of Bob's authenticator registers, so that the original keeps Bob's user handle.
	same := *bob.auth
	if got := e.addKey(alice.actor, ticket, &same, "Theirs"); got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonCeremonyFailed {
		t.Fatalf("adding another user's authenticator = %+v, want denied as a failed ceremony", got)
	}

	// The step-up was not spent by the refusal: Alice adds her own spare key with it.
	if got := e.addKey(alice.actor, ticket, testutil.NewSoftAuthenticator(t, rpID, origin), "Spare"); got.Outcome != passkey.OutcomeOK {
		t.Errorf("adding Alice's own authenticator = %+v", got)
	}

	if a, b := len(e.credentials(alice.user)), len(e.credentials(bob.user)); a != 2 || b != 1 {
		t.Errorf("keys: Alice %d, Bob %d; want 2 and 1", a, b)
	}

	if r := e.signIn(bob.auth, "", e.newBinding()); r.Outcome != passkey.OutcomeOK || r.Session.UserID() != bob.user.ID() {
		t.Errorf("Bob's key after the refusal = %+v", r)
	}
}
