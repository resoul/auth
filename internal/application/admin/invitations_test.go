package admin_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.airlance.org/auth/internal/application/admin"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
)

func TestCreateInvitationQueuesTheMailAndIsAudited(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	in := e.signedIn("ops@example.test")

	res, err := e.invitations.Create(ctx, admin.CreateInvitationCommand{Actor: in.actor, Email: " Guest@Example.test "})
	must(t, err)

	if res.Outcome != admin.OutcomeOK || res.Invitation.Email().String() != "guest@example.test" {
		t.Fatalf("Create = %+v", res)
	}

	if want := t0.Add(admin.DefaultInvitationTTL); !res.Invitation.ExpiresAt().Equal(want) {
		t.Errorf("ExpiresAt = %v, want the default lifetime", res.Invitation.ExpiresAt())
	}

	jobs := e.store.OutboxJobs()
	if len(jobs) != 1 || jobs[0].Kind != port.JobInvitation || jobs[0].Recipient.String() != "guest@example.test" {
		t.Errorf("outbox = %+v", jobs)
	}

	if got := e.auditOf(port.AuditAdminAction); len(got) != 1 || got[0].Fields["operation"] != "invite" || got[0].OperatorID != in.actor.OperatorID || !got[0].UserID.IsZero() {
		t.Errorf("audit = %+v", got)
	}

	list, err := e.invitations.List(ctx, in.actor)
	must(t, err)

	if list.Outcome != admin.OutcomeOK || len(list.Invitations) != 1 {
		t.Fatalf("List = %+v", list)
	}

	// Inviting again renews the invitation and sends the mail again.
	e.clock.Advance(10 * time.Minute)

	if _, err := e.invitations.Create(ctx, admin.CreateInvitationCommand{Actor: in.actor, Email: "guest@example.test", TTL: 48 * time.Hour}); err != nil {
		t.Fatal(err)
	}

	list, err = e.invitations.List(ctx, in.actor)
	must(t, err)

	if len(list.Invitations) != 1 || !list.Invitations[0].ExpiresAt().Equal(t0.Add(10*time.Minute+48*time.Hour)) || len(e.store.OutboxJobs()) != 2 {
		t.Errorf("renewal: %d invitations, %d mails", len(list.Invitations), len(e.store.OutboxJobs()))
	}
}

func TestCreateInvitationWithoutMail(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	in := e.signedIn("ops@example.test")
	res, err := e.invitations.Create(ctx, admin.CreateInvitationCommand{Actor: in.actor, Email: "guest@example.test", NoMail: true})
	must(t, err)

	if res.Outcome != admin.OutcomeOK || len(e.store.OutboxJobs()) != 0 {
		t.Errorf("Create = %+v, %d mails", res, len(e.store.OutboxJobs()))
	}
}

func TestAnAddressWithAnAccountIsNotInvited(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	in := e.signedIn("ops@example.test")
	e.user("member@example.test")
	res, err := e.invitations.Create(ctx, admin.CreateInvitationCommand{Actor: in.actor, Email: "member@example.test"})
	must(t, err)

	if res.Outcome != admin.OutcomeConflict || res.Reason != admin.ReasonAlreadyUser || res.Invitation != nil {
		t.Errorf("Create = %+v", res)
	}

	list, err := e.invitations.List(ctx, in.actor)
	must(t, err)

	if len(list.Invitations) != 0 || len(e.store.OutboxJobs()) != 0 || len(e.auditOf(port.AuditAdminAction)) != 0 {
		t.Error("a refused invitation left a trace")
	}
}

func TestInvitationInputIsChecked(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	in := e.signedIn("ops@example.test")
	for name, cmd := range map[string]admin.CreateInvitationCommand{
		"bad address":  {Email: "not an address"},
		"empty":        {Email: ""},
		"too short":    {Email: "g@example.test", TTL: time.Minute},
		"too long":     {Email: "g@example.test", TTL: identity.MaxInvitationTTL + time.Hour},
		"negative ttl": {Email: "g@example.test", TTL: -time.Hour},
	} {
		cmd.Actor = in.actor
		if _, err := e.invitations.Create(ctx, cmd); !errors.Is(err, admin.ErrInvalidInput) {
			t.Errorf("%s: error = %v, want ErrInvalidInput", name, err)
		}
	}

	if _, err := e.invitations.Revoke(ctx, admin.RevokeInvitationCommand{Actor: in.actor, Email: "nonsense"}); !errors.Is(err, admin.ErrInvalidInput) {
		t.Errorf("Revoke of a bad address: %v", err)
	}

	for _, ttl := range []time.Duration{identity.MinInvitationTTL, identity.MaxInvitationTTL} {
		if r, err := e.invitations.Create(ctx, admin.CreateInvitationCommand{Actor: in.actor, Email: "edge@example.test", TTL: ttl}); err != nil || r.Outcome != admin.OutcomeOK {
			t.Errorf("TTL %v: %+v, %v", ttl, r, err)
		}
	}
}

func TestRevokeInvitation(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	in := e.signedIn("ops@example.test")
	if _, err := e.invitations.Create(ctx, admin.CreateInvitationCommand{Actor: in.actor, Email: "guest@example.test", NoMail: true}); err != nil {
		t.Fatal(err)
	}

	res, err := e.invitations.Revoke(ctx, admin.RevokeInvitationCommand{Actor: in.actor, Email: "GUEST@example.test"})
	must(t, err)

	if res.Outcome != admin.OutcomeOK {
		t.Fatalf("Revoke = %+v", res)
	}

	if again, err := e.invitations.Revoke(ctx, admin.RevokeInvitationCommand{Actor: in.actor, Email: "guest@example.test"}); err != nil || again.Outcome != admin.OutcomeNotFound {
		t.Errorf("revoking twice = %+v, %v", again, err)
	}

	acts := e.auditOf(port.AuditAdminAction)
	revokes := 0

	for _, a := range acts {
		if a.Fields["operation"] == "uninvite" {
			revokes++
		}
	}

	if revokes != 1 {
		t.Errorf("uninvite events = %d, want 1 (a refused revoke is not an act)", revokes)
	}
}

func TestSharedInviteIsTheOneTheCommandLineUses(t *testing.T) {
	// The command line calls Invite inside its own transaction, without an operator.
	e := newEnv(t)
	email, err := identity.ParseEmail("cli@example.test")
	must(t, err)

	var registered bool

	e.do(func(ctx context.Context, s port.Stores) error {
		inv, reg, err := admin.Invite(ctx, s, email, e.clock.Now(), 24*time.Hour, false)
		registered = reg

		if err == nil && inv == nil {
			t.Error("Invite returned no invitation")
		}

		return err
	})

	if registered || len(e.store.OutboxJobs()) != 1 {
		t.Errorf("registered %v, mails %d", registered, len(e.store.OutboxJobs()))
	}

	e.do(func(ctx context.Context, s port.Stores) error {
		_, _, err := admin.Invite(ctx, s, email, e.clock.Now(), time.Minute, false)
		if err == nil {
			t.Error("a lifetime that is too short was accepted")
		}

		return nil
	})
}
