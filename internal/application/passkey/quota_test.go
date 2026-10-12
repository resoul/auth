package passkey_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"airlance.org/auth/internal/adapter/memory"
	"airlance.org/auth/internal/application/passkey"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/identity"
	dpasskey "airlance.org/auth/internal/domain/passkey"
	"airlance.org/auth/internal/domain/quota"
	"airlance.org/auth/internal/testutil"
)

// quotaEnv is an env whose passkey budgets are small enough to run out.
func quotaEnv(t *testing.T, windows map[quota.Scope][]quota.Window) *env {
	t.Helper()
	profile, err := quota.NewProfile(windows)
	if err != nil {
		t.Fatal(err)
	}
	return newEnvWith(t, nil, nil, memory.WithQuota(profile))
}

func TestStartingAssertionsIsLimitedPerAddress(t *testing.T) {
	e := quotaEnv(t, map[quota.Scope][]quota.Window{quota.PasskeyIP: {{Limit: 3, Per: time.Hour}}})
	begin := func(ip string) passkey.CeremonyResult {
		t.Helper()
		var addr netip.Addr
		if ip != "" {
			addr = netip.MustParseAddr(ip)
		}
		res, err := e.beginLogin.Execute(context.Background(), passkey.BeginLoginCommand{ClientIP: addr})
		must(t, err)
		return res
	}
	for range 3 {
		if res := begin("203.0.113.1"); res.Outcome != passkey.OutcomeOK {
			t.Fatalf("within the budget = %+v", res)
		}
	}
	if res := begin("203.0.113.1"); res.Outcome != passkey.OutcomeRateLimited || res.Reason != passkey.ReasonQuota || res.ChallengeID != "" || len(res.Options) != 0 {
		t.Errorf("over the budget = %+v, want a refusal that hands out nothing", res)
	}
	if res := begin("203.0.113.2"); res.Outcome != passkey.OutcomeOK {
		t.Errorf("another address = %+v", res)
	}
	// An IPv6 client rotating inside its /64 does not get a new budget.
	for range 3 {
		begin("2001:db8:1:2::1")
	}
	if res := begin("2001:db8:1:2:ffff::9"); res.Outcome != passkey.OutcomeRateLimited {
		t.Errorf("another address of the same /64 = %+v", res)
	}
	// An unknown address is not unlimited: all of them share one budget.
	for range 3 {
		begin("")
	}
	if res := begin(""); res.Outcome != passkey.OutcomeRateLimited {
		t.Errorf("unknown address = %+v", res)
	}
	// The window slides: an hour later the budget is back.
	e.clock.Advance(time.Hour)
	if res := begin("203.0.113.1"); res.Outcome != passkey.OutcomeOK {
		t.Errorf("after the window = %+v", res)
	}
}

func TestARefusedStartWritesNoChallenge(t *testing.T) {
	e := quotaEnv(t, map[quota.Scope][]quota.Window{quota.PasskeyIP: {{Limit: 1, Per: time.Hour}}})
	first, _ := e.beginLogin.Execute(context.Background(), passkey.BeginLoginCommand{})
	refused, _ := e.beginLogin.Execute(context.Background(), passkey.BeginLoginCommand{})
	if first.Outcome != passkey.OutcomeOK || refused.Outcome != passkey.OutcomeRateLimited {
		t.Fatalf("first %+v, refused %+v", first, refused)
	}
	id, _ := dpasskey.ParseID(first.ChallengeID)
	e.do(func(ctx context.Context, st port.Stores) error {
		if _, err := st.Challenges.GetForUpdate(ctx, id); err != nil {
			t.Errorf("the admitted challenge is missing: %v", err)
		}
		return nil
	})
	if got := e.store.Spent(port.SpendPasskey, identity.Email{}); got != 1 {
		t.Errorf("%d spends admitted, want 1: a refusal charges nothing", got)
	}
}

func TestStartingRegistrationsIsLimitedPerTicket(t *testing.T) {
	e := quotaEnv(t, map[quota.Scope][]quota.Window{quota.PasskeyRef: {{Limit: 2, Per: time.Hour}}})
	user := e.newUser()
	b := e.newBinding()
	first := e.ticketFor(user, dpasskey.TicketEnroll, b)
	begin := func(ticket string) passkey.CeremonyResult {
		t.Helper()
		res, err := e.beginEnroll.Execute(context.Background(), passkey.BeginEnrollCommand{TicketSecret: ticket, BindingSecret: b.secret})
		must(t, err)
		return res
	}
	begin(first)
	begin(first)
	if res := begin(first); res.Outcome != passkey.OutcomeRateLimited || res.Reason != passkey.ReasonQuota {
		t.Errorf("third start of one ticket = %+v", res)
	}
	// The budget belongs to the ticket: a ticket of the same user, from another proof, has its own.
	if res := begin(e.ticketFor(user, dpasskey.TicketEnroll, b)); res.Outcome != passkey.OutcomeOK {
		t.Errorf("another ticket = %+v", res)
	}
	// A limited ticket still finishes a ceremony that was started earlier.
	auth := testutil.NewSoftAuthenticator(t, rpID, origin)
	e.clock.Advance(time.Minute)
	fresh := e.ticketFor(user, dpasskey.TicketEnroll, b)
	started := begin(fresh)
	got, err := e.finishEnroll.Execute(context.Background(), passkey.FinishEnrollCommand{
		TicketSecret: fresh, BindingSecret: b.secret, ChallengeID: started.ChallengeID, Response: auth.Register(started.Options),
	})
	must(t, err)
	if got.Outcome != passkey.OutcomeOK {
		t.Errorf("finish = %+v", got)
	}
}

func TestARefusedTicketSpendsNoBudget(t *testing.T) {
	e := quotaEnv(t, map[quota.Scope][]quota.Window{quota.PasskeyIP: {{Limit: 1, Per: time.Hour}}})
	b := e.newBinding()
	unknown, _, _ := e.tickets.NewTicketSecret()
	for range 5 {
		res, err := e.beginEnroll.Execute(context.Background(), passkey.BeginEnrollCommand{TicketSecret: unknown, BindingSecret: b.secret})
		must(t, err)
		if res.Outcome != passkey.OutcomeDenied {
			t.Fatalf("unknown ticket = %+v", res)
		}
	}
	user := e.newUser()
	good := e.ticketFor(user, dpasskey.TicketEnroll, b)
	if res, _ := e.beginEnroll.Execute(context.Background(), passkey.BeginEnrollCommand{TicketSecret: good, BindingSecret: b.secret}); res.Outcome != passkey.OutcomeOK {
		t.Errorf("a real ticket after refused guesses = %+v: guesses must not eat the budget of honest users", res)
	}
}
