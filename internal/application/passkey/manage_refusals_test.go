package passkey_test

import (
	"context"
	"testing"

	"go.airlance.org/auth/internal/application/passkey"
	dpasskey "go.airlance.org/auth/internal/domain/passkey"
	"go.airlance.org/auth/internal/testutil"
)

func TestManagingPasskeysNeedsAnActiveSession(t *testing.T) {
	e := newEnv(t)

	h := e.enroll()
	if got := e.addKey(h.actor, e.stepUp(h.actor, h.auth, dpasskey.OperationAddPasskey), testutil.NewSoftAuthenticator(t, rpID, origin), "second"); got.Outcome != passkey.OutcomeOK {
		t.Fatalf("add = %+v", got)
	}

	keyID := e.credentials(h.user)[1].ID().String()
	ticket := e.stepUp(h.actor, h.auth, dpasskey.OperationDeletePasskey)
	e.revokeSession(h.actor)

	listed, err := e.list.Execute(context.Background(), h.actor)
	must(t, err)

	if listed.Outcome != passkey.OutcomeDenied || len(listed.Credentials) != 0 {
		t.Errorf("list on a revoked session = %+v", listed)
	}

	renamed, err := e.rename.Execute(context.Background(), passkey.RenameCommand{Actor: h.actor, ID: keyID, Name: "mine"})
	must(t, err)

	if renamed.Outcome != passkey.OutcomeDenied {
		t.Errorf("rename on a revoked session = %+v", renamed)
	}

	deleted, err := e.deleteKey.Execute(context.Background(), passkey.DeleteCommand{Actor: h.actor, StepUpSecret: ticket, ID: keyID})
	must(t, err)

	if deleted.Outcome != passkey.OutcomeDenied || deleted.Reason != passkey.ReasonNoSession {
		t.Errorf("delete on a revoked session = %+v", deleted)
	}

	if n := len(e.credentials(h.user)); n != 2 {
		t.Errorf("%d keys, want 2: a revoked session changed them", n)
	}
}

func TestDeletingAKeyThatIsNotThereIsNotFound(t *testing.T) {
	e := newEnv(t)

	h := e.enroll()
	for _, id := range []string{"not-an-id", unknownChallenge} {
		ticket := e.stepUp(h.actor, h.auth, dpasskey.OperationDeletePasskey)
		got, err := e.deleteKey.Execute(context.Background(), passkey.DeleteCommand{Actor: h.actor, StepUpSecret: ticket, ID: id})
		must(t, err)

		if got.Outcome != passkey.OutcomeNotFound || got.Reason != passkey.ReasonUnknownKeyID {
			t.Errorf("delete %q = %+v", id, got)
		}
	}

	if n := len(e.credentials(h.user)); n != 1 {
		t.Errorf("%d keys, want the one left", n)
	}
}
