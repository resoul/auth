package passkey_test

import (
	"context"
	"testing"
	"time"

	"go.airlance.org/auth/internal/adapter/memory"
	"go.airlance.org/auth/internal/application/passkey"
	appsession "go.airlance.org/auth/internal/application/session"
	dpasskey "go.airlance.org/auth/internal/domain/passkey"
	"go.airlance.org/auth/internal/domain/quota"
	"go.airlance.org/auth/internal/testutil"
)

// unknownChallenge is a well-formed challenge id that no ceremony ever created.
const unknownChallenge = "0198a2b4-7c3d-7e5f-8a1b-2c3d4e5f6a7c"

// startAdd begins an addition with the step-up ticket.
func (e *env) startAdd(actor appsession.Actor, ticket string) passkey.CeremonyResult {
	e.t.Helper()
	begun, err := e.beginAdd.Execute(context.Background(), passkey.BeginAddCommand{Actor: actor, StepUpSecret: ticket})
	must(e.t, err)

	return begun
}

// finishAddWith finishes an addition with the given parts, so a test can leave one of them out or change it.
func (e *env) finishAddWith(actor appsession.Actor, ticket, challengeID string, response []byte) passkey.FinishAddResult {
	e.t.Helper()
	got, err := e.finishAdd.Execute(context.Background(), passkey.FinishAddCommand{
		Actor: actor, StepUpSecret: ticket, ChallengeID: challengeID, Response: response,
	})
	must(e.t, err)

	return got
}

func TestAddingAPasskeyNeedsAnActiveSession(t *testing.T) {
	e := newEnv(t)
	h := e.enroll()
	ticket := e.stepUp(h.actor, h.auth, dpasskey.OperationAddPasskey)
	e.revokeSession(h.actor)

	if begun := e.startAdd(h.actor, ticket); begun.Outcome != passkey.OutcomeDenied || begun.Reason != passkey.ReasonNoSession || begun.ChallengeID != "" {
		t.Errorf("begin on a revoked session = %+v", begun)
	}

	if got := e.finishAddWith(h.actor, ticket, unknownChallenge, nil); got.Outcome != passkey.OutcomeDenied || got.Reason != passkey.ReasonNoSession {
		t.Errorf("finish on a revoked session = %+v", got)
	}

	if n := len(e.credentials(h.user)); n != 1 {
		t.Errorf("%d keys, want 1: a revoked session added one", n)
	}
}

func TestAFinishWithoutTheStepUpLeavesTheChallengeForTheRightTry(t *testing.T) {
	e := newEnv(t)
	h := e.enroll()
	ticket := e.stepUp(h.actor, h.auth, dpasskey.OperationAddPasskey)

	begun := e.startAdd(h.actor, ticket)
	if begun.Outcome != passkey.OutcomeOK {
		t.Fatalf("begin = %+v", begun)
	}

	// The step-up is checked before the challenge is read, so a refusal for want of it spends nothing.
	if got := e.finishAddWith(h.actor, "", begun.ChallengeID, nil); got.Outcome != passkey.OutcomeStepUpRequired || got.Reason != passkey.ReasonStepUp {
		t.Fatalf("finish without a step-up = %+v", got)
	}

	auth := testutil.NewSoftAuthenticator(t, rpID, origin)

	got := e.finishAddWith(h.actor, ticket, begun.ChallengeID, auth.Register(begun.Options))
	if got.Outcome != passkey.OutcomeOK {
		t.Errorf("the same challenge with the step-up = %+v", got)
	}
}

func TestAChallengeSpentByARefusedCeremonyCannotBeRetried(t *testing.T) {
	e := newEnv(t)
	h := e.enroll()
	ticket := e.stepUp(h.actor, h.auth, dpasskey.OperationAddPasskey)

	begun := e.startAdd(h.actor, ticket)
	if begun.Outcome != passkey.OutcomeOK {
		t.Fatalf("begin = %+v", begun)
	}

	weak := testutil.NewSoftAuthenticator(t, rpID, origin)

	weak.SkipUserVerification = true
	if got := e.finishAddWith(h.actor, ticket, begun.ChallengeID, weak.Register(begun.Options)); got.Reason != passkey.ReasonCeremonyFailed {
		t.Fatalf("a ceremony without user verification = %+v", got)
	}

	// The challenge is spent: a sound ceremony on it, with the same ticket, is refused too.
	sound := testutil.NewSoftAuthenticator(t, rpID, origin)

	again := e.finishAddWith(h.actor, ticket, begun.ChallengeID, sound.Register(begun.Options))
	if again.Outcome != passkey.OutcomeDenied || again.Reason != passkey.ReasonBadChallenge {
		t.Errorf("a reused challenge = %+v", again)
	}

	if n := len(e.credentials(h.user)); n != 1 {
		t.Errorf("%d keys, want 1", n)
	}
}

func TestTheLastFreeSlotIsTakenByOneOfTwoOpenCeremonies(t *testing.T) {
	e := newEnv(t)
	h := e.enroll()
	// Fill up to one free slot.
	for range dpasskey.MaxPerUser - 2 {
		if got := e.addKey(h.actor, e.stepUp(h.actor, h.auth, dpasskey.OperationAddPasskey), testutil.NewSoftAuthenticator(t, rpID, origin), "k"); got.Outcome != passkey.OutcomeOK {
			t.Fatalf("filling up = %+v", got)
		}
	}

	if n := len(e.credentials(h.user)); n != dpasskey.MaxPerUser-1 {
		t.Fatalf("%d keys, want %d", n, dpasskey.MaxPerUser-1)
	}

	// Two ceremonies are open while one slot is free: both may start, but only one may finish.
	firstTicket := e.stepUp(h.actor, h.auth, dpasskey.OperationAddPasskey)
	secondTicket := e.stepUp(h.actor, h.auth, dpasskey.OperationAddPasskey)

	first, second := e.startAdd(h.actor, firstTicket), e.startAdd(h.actor, secondTicket)
	if first.Outcome != passkey.OutcomeOK || second.Outcome != passkey.OutcomeOK {
		t.Fatalf("begin = %+v and %+v", first, second)
	}

	if got := e.finishAddWith(h.actor, firstTicket, first.ChallengeID, testutil.NewSoftAuthenticator(t, rpID, origin).Register(first.Options)); got.Outcome != passkey.OutcomeOK {
		t.Fatalf("the first finish = %+v", got)
	}

	got := e.finishAddWith(h.actor, secondTicket, second.ChallengeID, testutil.NewSoftAuthenticator(t, rpID, origin).Register(second.Options))
	if got.Outcome != passkey.OutcomeConflict || got.Reason != passkey.ReasonTooManyKeys {
		t.Errorf("the second finish = %+v, want too many keys", got)
	}

	if n := len(e.credentials(h.user)); n != dpasskey.MaxPerUser {
		t.Errorf("%d keys, want exactly %d", n, dpasskey.MaxPerUser)
	}
}

func TestAddingAPasskeyIsRateLimitedPerTicket(t *testing.T) {
	profile, err := quota.NewProfile(map[quota.Scope][]quota.Window{quota.PasskeyRef: {{Limit: 1, Per: time.Hour}}})
	if err != nil {
		t.Fatal(err)
	}

	e := newEnvWith(t, nil, nil, memory.WithQuota(profile))
	h := e.enroll()
	ticket := e.stepUp(h.actor, h.auth, dpasskey.OperationAddPasskey)

	if begun := e.startAdd(h.actor, ticket); begun.Outcome != passkey.OutcomeOK {
		t.Fatalf("the first start = %+v", begun)
	}
	// A ticket starts one ceremony per window, so it cannot be used to probe for a fresh challenge forever.
	if begun := e.startAdd(h.actor, ticket); begun.Outcome != passkey.OutcomeRateLimited || begun.Reason != passkey.ReasonQuota {
		t.Errorf("the second start = %+v", begun)
	}
}
