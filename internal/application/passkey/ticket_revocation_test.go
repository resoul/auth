package passkey_test

import (
	"context"
	"testing"

	"go.airlance.org/auth/internal/application/passkey"
	dpasskey "go.airlance.org/auth/internal/domain/passkey"
	"go.airlance.org/auth/internal/testutil"
)

// A change of the account's protection spends every ticket issued before it. These scenarios run on the in-memory
// store here and on PostgreSQL in postgres_integration_test.go.

func TestStaleRecoveryTicketAfterAnotherRecovery(t *testing.T) {
	staleRecoveryTicketAfterAnotherRecovery(t, newEnv(t))
}

func TestStaleRecoveryTicketAfterNewRecoveryCodes(t *testing.T) {
	staleRecoveryTicketAfterNewRecoveryCodes(t, newEnv(t))
}

func TestNewRecoveryCodesKeepTheStepUpOfTheirSession(t *testing.T) {
	newRecoveryCodesKeepTheStepUpOfTheirSession(t, newEnv(t))
}

func TestStaleRecoveryTicketAfterADeletedKey(t *testing.T) {
	staleRecoveryTicketAfterADeletedKey(t, newEnv(t))
}

// stolenRecovery is what someone who reads the mailbox and holds one recovery code gets: a recovery ticket redeemed
// with the code and a registration of their own key begun with it.
type stolenRecovery struct {
	holder  enrolled
	ticket  string
	binding bindingSecret
	auth    *testutil.SoftAuthenticator
	begun   passkey.CeremonyResult
}

// stealRecovery redeems the code and begins the registration, then leaves the ticket waiting.
func (e *env) stealRecovery(h enrolled, code string) stolenRecovery {
	e.t.Helper()

	b := e.newBinding()

	redeemed := e.redeem(e.ticketFor(h.user, dpasskey.TicketSecondFactor, b), b, code)
	if redeemed.Outcome != passkey.OutcomeOK {
		e.t.Fatalf("redeem = %+v", redeemed)
	}

	begun, err := e.beginEnroll.Execute(context.Background(), passkey.BeginEnrollCommand{TicketSecret: redeemed.TicketSecret, BindingSecret: b.secret})
	must(e.t, err)

	if begun.Outcome != passkey.OutcomeOK {
		e.t.Fatalf("begin enroll = %+v", begun)
	}

	return stolenRecovery{holder: h, ticket: redeemed.TicketSecret, binding: b, auth: testutil.NewSoftAuthenticator(e.t, rpID, origin), begun: begun}
}

// assertStale checks that the stolen ticket neither finishes the ceremony it began nor begins a new one.
func (e *env) assertStale(s stolenRecovery) {
	e.t.Helper()

	finished, err := e.finishEnroll.Execute(context.Background(), passkey.FinishEnrollCommand{
		TicketSecret: s.ticket, BindingSecret: s.binding.secret, ChallengeID: s.begun.ChallengeID, Response: s.auth.Register(s.begun.Options),
		CredentialName: "Theirs", DeviceName: "theirs",
	})
	must(e.t, err)

	if finished.Outcome != passkey.OutcomeDenied || finished.Reason != passkey.ReasonBadTicket {
		e.t.Errorf("finishing the ceremony begun with the stale ticket = %+v, want denied for a bad ticket", finished)
	}

	if again := e.enrollWith(s.holder.user, s.auth, s.ticket, s.binding); again.Outcome != passkey.OutcomeDenied || again.Reason != passkey.ReasonBadTicket {
		e.t.Errorf("a new ceremony with the stale ticket = %+v, want denied for a bad ticket", again)
	}

	if r := e.signIn(s.auth, "", e.newBinding()); r.Outcome == passkey.OutcomeOK {
		e.t.Error("the key of the stale ticket signs in")
	}
}

func staleRecoveryTicketAfterAnotherRecovery(t *testing.T, e *env) {
	holder := e.enroll()
	stolen := e.stealRecovery(holder, holder.codes[0])

	// The owner recovers with another code and a new key.
	b := e.newBinding()

	own := e.redeem(e.ticketFor(holder.user, dpasskey.TicketSecondFactor, b), b, holder.codes[1])
	if own.Outcome != passkey.OutcomeOK {
		t.Fatalf("owner redeem = %+v", own)
	}

	fresh := testutil.NewSoftAuthenticator(t, rpID, origin)
	if got := e.enrollWith(holder.user, fresh, own.TicketSecret, b); got.Outcome != passkey.OutcomeOK {
		t.Fatalf("owner recovery = %+v", got)
	}

	e.assertStale(stolen)

	if n := len(e.credentials(holder.user)); n != 1 {
		t.Errorf("%d keys, want only the owner's new one", n)
	}

	if r := e.signIn(fresh, "", e.newBinding()); r.Outcome != passkey.OutcomeOK {
		t.Errorf("the owner's new key does not sign in: %+v", r)
	}
}

func staleRecoveryTicketAfterNewRecoveryCodes(t *testing.T, e *env) {
	holder := e.enroll()
	stolen := e.stealRecovery(holder, holder.codes[0])

	regenerated, err := e.regenerate.Execute(context.Background(), passkey.RegenerateCommand{
		Actor: holder.actor, StepUpSecret: e.stepUp(holder.actor, holder.auth, dpasskey.OperationRegenerateCodes),
	})
	must(t, err)

	if regenerated.Outcome != passkey.OutcomeOK {
		t.Fatalf("regenerate = %+v", regenerated)
	}

	e.assertStale(stolen)

	if n := len(e.credentials(holder.user)); n != 1 {
		t.Errorf("%d keys, want only the owner's", n)
	}

	if r := e.signIn(holder.auth, "", e.newBinding()); r.Outcome != passkey.OutcomeOK {
		t.Errorf("the owner's key does not sign in: %+v", r)
	}
}

func newRecoveryCodesKeepTheStepUpOfTheirSession(t *testing.T, e *env) {
	holder := e.enroll()
	other := e.secondSession(holder)

	// Both sessions proved the key for adding another one; then the first issues new codes.
	mine := e.stepUp(holder.actor, holder.auth, dpasskey.OperationAddPasskey)
	theirs := e.stepUp(other, holder.auth, dpasskey.OperationAddPasskey)

	regenerated, err := e.regenerate.Execute(context.Background(), passkey.RegenerateCommand{
		Actor: holder.actor, StepUpSecret: e.stepUp(holder.actor, holder.auth, dpasskey.OperationRegenerateCodes),
	})
	must(t, err)

	if regenerated.Outcome != passkey.OutcomeOK {
		t.Fatalf("regenerate = %+v", regenerated)
	}

	if got := e.addKey(other, theirs, testutil.NewSoftAuthenticator(t, rpID, origin), "Theirs"); got.Outcome != passkey.OutcomeStepUpRequired {
		t.Errorf("the step-up of another session after new codes = %+v, want a new step-up required", got)
	}

	if got := e.addKey(holder.actor, mine, testutil.NewSoftAuthenticator(t, rpID, origin), "Mine"); got.Outcome != passkey.OutcomeOK {
		t.Errorf("the step-up of the session that issued the codes = %+v, want it to stay usable", got)
	}
}

func staleRecoveryTicketAfterADeletedKey(t *testing.T, e *env) {
	holder := e.enroll()

	spare := testutil.NewSoftAuthenticator(t, rpID, origin)
	if got := e.addKey(holder.actor, e.stepUp(holder.actor, holder.auth, dpasskey.OperationAddPasskey), spare, "Spare"); got.Outcome != passkey.OutcomeOK {
		t.Fatalf("add spare key = %+v", got)
	}

	stolen := e.stealRecovery(holder, holder.codes[0])

	deleted, err := e.deleteKey.Execute(context.Background(), passkey.DeleteCommand{
		Actor: holder.actor, StepUpSecret: e.stepUp(holder.actor, holder.auth, dpasskey.OperationDeletePasskey),
		ID: e.credentials(holder.user)[1].ID().String(),
	})
	must(t, err)

	if deleted.Outcome != passkey.OutcomeOK {
		t.Fatalf("delete = %+v", deleted)
	}

	e.assertStale(stolen)

	if r := e.signIn(holder.auth, "", e.newBinding()); r.Outcome != passkey.OutcomeOK {
		t.Errorf("the owner's remaining key does not sign in: %+v", r)
	}
}
