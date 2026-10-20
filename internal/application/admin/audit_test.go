package admin_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"go.airlance.org/auth/internal/application/admin"
	"go.airlance.org/auth/internal/application/port"
)

func TestAuditListFiltersAndPages(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	in := e.signedIn("ops@example.test")

	a, b := e.user("a@example.test"), e.user("b@example.test")
	for _, u := range []string{a.ID().String(), b.ID().String(), a.ID().String()} {
		e.clock.Advance(time.Second)

		if _, err := e.users.RevokeSessions(ctx, admin.UserCommand{Actor: in.actor, UserID: u}); err != nil {
			t.Fatal(err)
		}
	}

	all, err := e.audit.List(ctx, admin.ListAuditCommand{Actor: in.actor})
	must(t, err)

	if all.Outcome != admin.OutcomeOK || len(all.Entries) < 5 || all.Next != "" {
		t.Fatalf("all = %d entries, next %q", len(all.Entries), all.Next)
	}

	for i := 1; i < len(all.Entries); i++ {
		if all.Entries[i].At.After(all.Entries[i-1].At) {
			t.Fatal("entries are not newest first")
		}
	}

	byUser, err := e.audit.List(ctx, admin.ListAuditCommand{Actor: in.actor, UserID: a.ID().String(), Type: string(port.AuditAdminAction)})
	must(t, err)

	if len(byUser.Entries) != 2 {
		t.Errorf("acts on a = %d, want 2", len(byUser.Entries))
	}

	byOperator, err := e.audit.List(ctx, admin.ListAuditCommand{Actor: in.actor, OperatorID: in.actor.OperatorID.String(), Type: string(port.AuditAdminAction)})
	must(t, err)

	if len(byOperator.Entries) != 3 {
		t.Errorf("acts of the operator = %d, want 3", len(byOperator.Entries))
	}

	// Walk the whole log two at a time: every entry once, in order.
	var ids []string

	before := ""
	for {
		page, err := e.audit.List(ctx, admin.ListAuditCommand{Actor: in.actor, Before: before, Limit: 2})
		must(t, err)

		if len(page.Entries) > 2 {
			t.Fatalf("page of %d", len(page.Entries))
		}

		for _, en := range page.Entries {
			ids = append(ids, en.ID)
		}

		if page.Next == "" {
			break
		}

		before = page.Next
	}

	if len(ids) != len(all.Entries) {
		t.Fatalf("walked %d entries, want %d", len(ids), len(all.Entries))
	}

	for i, en := range all.Entries {
		if ids[i] != en.ID {
			t.Errorf("entry %d = %s, want %s", i, ids[i], en.ID)
		}
	}
}

func TestAuditListRejectsBadFilters(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)

	in := e.signedIn("ops@example.test")
	for name, cmd := range map[string]admin.ListAuditCommand{
		"user id":       {UserID: "nope"},
		"operator id":   {OperatorID: "nope"},
		"type":          {Type: "login.exploded"},
		"cursor":        {Before: "!!!"},
		"cursor shape":  {Before: "bm90IGEgY3Vyc29y"},
		"limit":         {Limit: -3},
		"limit too big": {Limit: admin.MaxPageSize + 1},
		"cursor time":   {Before: "MjAyNi0xMy00MXxpZA"},
	} {
		cmd.Actor = in.actor
		if _, err := e.audit.List(ctx, cmd); !errors.Is(err, admin.ErrInvalidInput) {
			t.Errorf("%s: error = %v, want ErrInvalidInput", name, err)
		}
	}

	if strings.Contains(string(port.AuditAdminAction), " ") {
		t.Fatal("unreachable") // keeps strings imported for the table above if it changes
	}
}
