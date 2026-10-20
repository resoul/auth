package admin_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"go.airlance.org/auth/internal/application/admin"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/operator"
	"go.airlance.org/auth/internal/domain/passkey"
	"go.airlance.org/auth/internal/domain/session"
	"go.airlance.org/auth/internal/testutil"
)

// signedInUser gives a user an open session and a key, as a real sign-in does.
func (e *env) openSession(u *identity.User) *session.Session {
	e.t.Helper()
	sess := e.factory.Session(testutil.SessionSpec{User: u})
	e.do(func(ctx context.Context, s port.Stores) error { return s.Sessions.Create(ctx, sess) })

	return sess
}

func (e *env) activeSessions(u *identity.User) int {
	e.t.Helper()

	var n int

	e.do(func(ctx context.Context, s port.Stores) error {
		list, err := s.Sessions.ListActive(ctx, u.ID(), e.clock.Now(), 50)
		n = len(list)

		return err
	})

	return n
}

func (e *env) stored(u *identity.User) *identity.User {
	e.t.Helper()

	var got *identity.User

	e.do(func(ctx context.Context, s port.Stores) error {
		var err error

		got, err = s.Users.Get(ctx, u.ID())

		return err
	})

	return got
}

func (e *env) exists(u *identity.User) bool {
	e.t.Helper()
	err := e.store.Do(context.Background(), func(ctx context.Context, s port.Stores) error {
		_, err := s.Users.Get(ctx, u.ID())
		return err
	})

	return err == nil
}

func TestEveryOperationNeedsALiveOperatorSession(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	in := e.signedIn("ops@example.test")
	target := e.user("target@example.test")
	e.openSession(target)

	// Actors that are not, or are no longer, signed in.
	revoked := e.signedIn("revoked@example.test")
	must(t, e.auth.Logout(ctx, revoked.actor))
	off := e.signedIn("off@example.test")
	_, err := e.operators.SetDisabled(ctx, "off@example.test", true)
	must(t, err)

	foreign := in.actor
	foreign.OperatorID = revoked.actor.OperatorID // a session that belongs to another operator

	id := target.ID().String()

	for name, actor := range map[string]admin.Actor{
		"zero": {}, "logged out": revoked.actor, "disabled operator": off.actor, "another operator's session": foreign,
	} {
		ops := map[string]func() (admin.Outcome, error){
			"list": func() (admin.Outcome, error) {
				r, err := e.users.List(ctx, admin.ListUsersCommand{Actor: actor})
				return r.Outcome, err
			},
			"get": func() (admin.Outcome, error) {
				r, err := e.users.Get(ctx, admin.UserCommand{Actor: actor, UserID: id})
				return r.Outcome, err
			},
			"block": func() (admin.Outcome, error) {
				r, err := e.users.Block(ctx, admin.UserCommand{Actor: actor, UserID: id})
				return r.Outcome, err
			},
			"unblock": func() (admin.Outcome, error) {
				r, err := e.users.Unblock(ctx, admin.UserCommand{Actor: actor, UserID: id})
				return r.Outcome, err
			},
			"revoke": func() (admin.Outcome, error) {
				r, err := e.users.RevokeSessions(ctx, admin.UserCommand{Actor: actor, UserID: id})
				return r.Outcome, err
			},
			"delete": func() (admin.Outcome, error) {
				r, err := e.users.Delete(ctx, admin.DeleteCommand{UserCommand: admin.UserCommand{Actor: actor, UserID: id}, ConfirmEmail: target.Email().String()})
				return r.Outcome, err
			},
			"invite": func() (admin.Outcome, error) {
				r, err := e.invitations.Create(ctx, admin.CreateInvitationCommand{Actor: actor, Email: "new@example.test"})
				return r.Outcome, err
			},
			"invitations": func() (admin.Outcome, error) {
				r, err := e.invitations.List(ctx, actor)
				return r.Outcome, err
			},
			"uninvite": func() (admin.Outcome, error) {
				r, err := e.invitations.Revoke(ctx, admin.RevokeInvitationCommand{Actor: actor, Email: "new@example.test"})
				return r.Outcome, err
			},
			"audit": func() (admin.Outcome, error) {
				r, err := e.audit.List(ctx, admin.ListAuditCommand{Actor: actor})
				return r.Outcome, err
			},
		}
		for op, run := range ops {
			if got, err := run(); err != nil || got != admin.OutcomeUnauthenticated {
				t.Errorf("%s / %s = %v, %v; want unauthenticated", name, op, got, err)
			}
		}
	}

	if e.stored(target).Blocked() || !e.exists(target) || e.activeSessions(target) != 1 {
		t.Error("an unauthenticated call changed the user")
	}

	if got := e.auditOf(port.AuditAdminAction); len(got) != 0 {
		t.Errorf("an unauthenticated call was audited as an act: %+v", got)
	}
}

func TestListUsersPagesInAddressOrderAndFilters(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	in := e.signedIn("ops@example.test")
	for _, email := range []string{"dave@example.test", "alice@example.test", "ann@example.test", "carol@example.test", "bob@example.test"} {
		e.user(email)
	}

	var seen []string

	after := ""
	for page := 0; ; page++ {
		res, err := e.users.List(ctx, admin.ListUsersCommand{Actor: in.actor, After: after, Limit: 2})
		must(t, err)

		if res.Outcome != admin.OutcomeOK || len(res.Users) > 2 {
			t.Fatalf("page %d = %+v", page, res)
		}

		for _, u := range res.Users {
			seen = append(seen, u.Email().String())
		}

		if res.Next == "" {
			break
		}

		if page > 5 {
			t.Fatal("the pages never end")
		}

		after = res.Next
	}

	if got, want := strings.Join(seen, ","), "alice@example.test,ann@example.test,bob@example.test,carol@example.test,dave@example.test"; got != want {
		t.Errorf("walked %s, want %s", got, want)
	}

	// A page that ends exactly at the last user has no next page.
	res, err := e.users.List(ctx, admin.ListUsersCommand{Actor: in.actor, Limit: 5})
	must(t, err)

	if len(res.Users) != 5 || res.Next != "" {
		t.Errorf("an exact page: %d users, next %q", len(res.Users), res.Next)
	}

	res, err = e.users.List(ctx, admin.ListUsersCommand{Actor: in.actor, Prefix: "  AN "})
	must(t, err)

	if len(res.Users) != 1 || res.Users[0].Email().String() != "ann@example.test" {
		t.Errorf("a case-insensitive prefix: %+v", res.Users)
	}
}

func TestListUsersRejectsBadInput(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	in := e.signedIn("ops@example.test")

	long := strings.Repeat("a", 255)
	for name, cmd := range map[string]admin.ListUsersCommand{
		"negative limit": {Limit: -1}, "huge limit": {Limit: admin.MaxPageSize + 1}, "long prefix": {Prefix: long}, "long cursor": {After: long},
	} {
		cmd.Actor = in.actor
		if _, err := e.users.List(ctx, cmd); !errors.Is(err, admin.ErrInvalidInput) {
			t.Errorf("%s: error = %v, want ErrInvalidInput", name, err)
		}
	}

	if r, err := e.users.List(ctx, admin.ListUsersCommand{Actor: in.actor, Limit: admin.MaxPageSize}); err != nil || r.Outcome != admin.OutcomeOK {
		t.Errorf("the largest page: %+v, %v", r, err)
	}
}

func TestUserCardShowsWhatTheUserHas(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	in := e.signedIn("ops@example.test")
	u := e.user("target@example.test")
	sess := e.openSession(u)
	key := e.factory.Credential(testutil.CredentialSpec{User: u, Name: "Phone"})
	e.do(func(ctx context.Context, s port.Stores) error {
		if err := s.Credentials.Create(ctx, key); err != nil {
			return err
		}

		codes := []*passkey.RecoveryCode{e.factory.RecoveryCode(u, "AAAA-BBBB"), e.factory.RecoveryCode(u, "CCCC-DDDD")}

		return s.Recovery.Replace(ctx, u.ID(), codes)
	})

	res, err := e.users.Get(ctx, admin.UserCommand{Actor: in.actor, UserID: u.ID().String()})
	must(t, err)

	if res.Outcome != admin.OutcomeOK {
		t.Fatalf("Get = %+v", res)
	}

	d := res.Detail
	if d.User.ID() != u.ID() || len(d.Sessions) != 1 || d.Sessions[0].ID() != sess.ID() || len(d.Keys) != 1 || d.Keys[0].Name() != "Phone" || d.RecoveryCodesLeft != 2 {
		t.Errorf("detail = %+v", d)
	}

	for _, id := range []string{"", "nope", identity0(), in.actor.OperatorID.String()[:35]} {
		if r, err := e.users.Get(ctx, admin.UserCommand{Actor: in.actor, UserID: id}); err != nil || r.Outcome != admin.OutcomeNotFound {
			t.Errorf("Get(%q) = %+v, %v; want not found", id, r, err)
		}
	}
}

// identity0 is a well-formed identifier of nobody.
func identity0() string { return "00000000-0000-4000-8000-0000000000ff" }

func TestBlockEndsEverythingAndIsAuditedAndRepeatable(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	in := e.signedIn("ops@example.test")
	u := e.user("target@example.test")
	e.openSession(u)
	e.openSession(u)
	bystander := e.user("bystander@example.test")
	e.openSession(bystander)

	res, err := e.users.Block(ctx, admin.UserCommand{Actor: in.actor, UserID: u.ID().String()})
	must(t, err)

	if res.Outcome != admin.OutcomeOK {
		t.Fatalf("Block = %+v", res)
	}

	if !e.stored(u).Blocked() || e.activeSessions(u) != 0 {
		t.Error("the user is not blocked or still has sessions")
	}

	if e.activeSessions(bystander) != 1 || e.stored(bystander).Blocked() {
		t.Error("the block touched another user")
	}

	first := e.stored(u).BlockedAt()

	e.clock.Advance(1)

	if res, err := e.users.Block(ctx, admin.UserCommand{Actor: in.actor, UserID: u.ID().String()}); err != nil || res.Outcome != admin.OutcomeOK {
		t.Fatalf("a second Block = %+v, %v", res, err)
	}

	if !e.stored(u).BlockedAt().Equal(first) {
		t.Error("blocking again moved the time")
	}

	acts := e.auditOf(port.AuditAdminAction)
	if len(acts) != 2 || acts[0].Fields["operation"] != "block" || acts[0].UserID != u.ID() || acts[0].OperatorID != in.actor.OperatorID || acts[0].Result != port.AuditSuccess {
		t.Errorf("audit = %+v", acts)
	}

	// Unblocking lets them sign in again but does not bring the sessions back.
	if res, err := e.users.Unblock(ctx, admin.UserCommand{Actor: in.actor, UserID: u.ID().String()}); err != nil || res.Outcome != admin.OutcomeOK {
		t.Fatalf("Unblock = %+v, %v", res, err)
	}

	if e.stored(u).Blocked() || e.activeSessions(u) != 0 {
		t.Error("unblock did not clear the flag or brought sessions back")
	}

	if got := e.auditOf(port.AuditAdminAction); len(got) != 3 || got[0].Fields["operation"] != "unblock" {
		t.Errorf("audit after unblock = %+v", got)
	}
}

func TestBlockingAnUnknownUserIsNotFoundAndLeavesNoTrace(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	in := e.signedIn("ops@example.test")

	for name, run := range map[string]func(id string) (admin.Result, error){
		"block": func(id string) (admin.Result, error) {
			return e.users.Block(ctx, admin.UserCommand{Actor: in.actor, UserID: id})
		},
		"unblock": func(id string) (admin.Result, error) {
			return e.users.Unblock(ctx, admin.UserCommand{Actor: in.actor, UserID: id})
		},
		"revoke": func(id string) (admin.Result, error) {
			return e.users.RevokeSessions(ctx, admin.UserCommand{Actor: in.actor, UserID: id})
		},
		"delete": func(id string) (admin.Result, error) {
			return e.users.Delete(ctx, admin.DeleteCommand{UserCommand: admin.UserCommand{Actor: in.actor, UserID: id}, ConfirmEmail: "x@example.test"})
		},
	} {
		for _, id := range []string{identity0(), "garbage", ""} {
			if r, err := run(id); err != nil || r.Outcome != admin.OutcomeNotFound {
				t.Errorf("%s(%q) = %+v, %v; want not found", name, id, r, err)
			}
		}
	}

	if got := e.auditOf(port.AuditAdminAction); len(got) != 0 {
		t.Errorf("audit = %+v", got)
	}
}

func TestRevokeSessionsEndsSessionsWithoutBlocking(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	in := e.signedIn("ops@example.test")
	u := e.user("target@example.test")
	e.openSession(u)
	e.openSession(u)

	res, err := e.users.RevokeSessions(ctx, admin.UserCommand{Actor: in.actor, UserID: u.ID().String()})
	must(t, err)

	if res.Outcome != admin.OutcomeOK || e.activeSessions(u) != 0 || e.stored(u).Blocked() {
		t.Errorf("RevokeSessions = %+v, sessions %d, blocked %v", res, e.activeSessions(u), e.stored(u).Blocked())
	}

	if got := e.auditOf(port.AuditAdminAction); len(got) != 1 || got[0].Fields["operation"] != "revoke_sessions" {
		t.Errorf("audit = %+v", got)
	}
}

func TestAnActThatCannotBeAuditedChangesNothing(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	in := e.signedIn("ops@example.test")
	u := e.user("target@example.test")
	e.openSession(u)

	e.faults.wrap = func(s port.Stores) port.Stores { s.Audit = failingAudit{s.Audit}; return s }
	if _, err := e.users.Block(ctx, admin.UserCommand{Actor: in.actor, UserID: u.ID().String()}); err == nil {
		t.Fatal("Block hid the audit failure")
	}

	e.faults.wrap = nil
	if e.stored(u).Blocked() || e.activeSessions(u) != 1 {
		t.Error("a block that could not be audited took effect")
	}
}

func TestDeleteNeedsFreshSignInAndTheUsersAddress(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	in := e.signedIn("ops@example.test")
	u := e.user("target@example.test")
	e.openSession(u)

	cmd := func(confirm string) admin.DeleteCommand {
		return admin.DeleteCommand{UserCommand: admin.UserCommand{Actor: in.actor, UserID: u.ID().String()}, ConfirmEmail: confirm}
	}

	for _, confirm := range []string{"", "other@example.test", "not an address", "target@example.test.evil"} {
		res, err := e.users.Delete(ctx, cmd(confirm))
		must(t, err)

		if res.Outcome != admin.OutcomeConflict || res.Reason != admin.ReasonConfirmMismatch || !e.exists(u) {
			t.Errorf("confirm %q: %+v, exists %v", confirm, res, e.exists(u))
		}
	}

	// The session is alive but its sign-in is older than FreshFor.
	e.clock.Advance(operator.FreshFor - 1)

	probe := e.user("probe@example.test")
	if r, err := e.users.Delete(ctx, admin.DeleteCommand{UserCommand: admin.UserCommand{Actor: in.actor, UserID: probe.ID().String()}, ConfirmEmail: probe.Email().String()}); err != nil || r.Outcome != admin.OutcomeOK {
		t.Fatalf("a sign-in just inside the window: %+v, %v", r, err)
	}

	e.clock.Advance(1)
	res, err := e.users.Delete(ctx, cmd("target@example.test"))
	must(t, err)

	if res.Outcome != admin.OutcomeReauthRequired || !e.exists(u) {
		t.Fatalf("an old sign-in: %+v, exists %v", res, e.exists(u))
	}
	// Other operations do not need a fresh sign-in.
	if r, err := e.users.Block(ctx, admin.UserCommand{Actor: in.actor, UserID: u.ID().String()}); err != nil || r.Outcome != admin.OutcomeOK {
		t.Errorf("Block with an old sign-in: %+v, %v", r, err)
	}

	// A new sign-in makes it work, and the address is matched without regard to case.
	again := e.login(in.operatorFixture)
	auth, err := e.auth.Authenticate(ctx, again.SessionSecret)
	must(t, err)

	del := admin.DeleteCommand{UserCommand: admin.UserCommand{Actor: auth.Actor, UserID: u.ID().String()}, ConfirmEmail: " Target@Example.test "}
	res, err = e.users.Delete(ctx, del)
	must(t, err)

	if res.Outcome != admin.OutcomeOK || e.exists(u) {
		t.Fatalf("Delete = %+v, exists %v", res, e.exists(u))
	}
	// The act stays in the log, with who did it and without whom.
	var deleted []port.AuditEvent

	for _, ev := range e.auditOf(port.AuditAdminAction) {
		if ev.Fields["operation"] == "delete_user" {
			deleted = append(deleted, ev)
		}
	}

	if len(deleted) != 2 || deleted[0].OperatorID != auth.Actor.OperatorID || !deleted[0].UserID.IsZero() {
		t.Errorf("delete audit = %+v", deleted)
	}
}

func TestPagedUserListReachesEveryUserWhateverThePageSize(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	in := e.signedIn("ops@example.test")

	const total = 11
	for i := 0; i < total; i++ {
		e.user(fmt.Sprintf("user%02d@example.test", i))
	}

	for size := 1; size <= 4; size++ {
		seen := map[string]bool{}

		after := ""
		for {
			res, err := e.users.List(ctx, admin.ListUsersCommand{Actor: in.actor, After: after, Limit: size})
			must(t, err)

			for _, u := range res.Users {
				if seen[u.Email().String()] {
					t.Fatalf("size %d: %s listed twice", size, u.Email())
				}

				seen[u.Email().String()] = true
			}

			if res.Next == "" {
				break
			}

			after = res.Next
		}

		if len(seen) != total {
			t.Errorf("size %d reached %d users, want %d", size, len(seen), total)
		}
	}
}
