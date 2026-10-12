package emailauth_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"airlance.org/auth/internal/application/emailauth"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/authflow"
	"airlance.org/auth/internal/domain/quota"
)

func (e *env) startFrom(email, binding, ip string) emailauth.StartResult {
	e.t.Helper()
	cmd := emailauth.StartCommand{Email: email, BindingSecret: binding}
	if ip != "" {
		cmd.ClientIP = netip.MustParseAddr(ip)
	}
	res, err := e.start.Execute(context.Background(), cmd)
	if err != nil {
		e.t.Fatalf("start: %v", err)
	}
	return res
}

func TestStartSpendsTheIPBudgetOfTheClientAddress(t *testing.T) {
	p, err := quota.NewProfile(map[quota.Scope][]quota.Window{quota.UnknownSendIP: {{Limit: 1, Per: time.Hour}}})
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, withQuota(p))

	if res := e.startFrom("alice@example.test", "", "192.0.2.1"); res.Outcome != emailauth.OutcomeOK {
		t.Fatalf("first start = %+v", res)
	}
	if res := e.startFrom("bob@example.test", "", "192.0.2.1"); res.Outcome != emailauth.OutcomeRateLimited || res.Reason != emailauth.ReasonQuota {
		t.Errorf("second start from the same IP = %+v, want rate limited", res)
	}
	if res := e.startFrom("bob@example.test", "", "192.0.2.2"); res.Outcome != emailauth.OutcomeOK {
		t.Errorf("another IP = %+v", res)
	}
	if res := e.startFrom("carol@example.test", "", ""); res.Outcome != emailauth.OutcomeOK {
		t.Errorf("an unknown IP = %+v, want no IP budget", res)
	}
	if e.store.FlowCount() != 3 || len(e.store.OutboxJobs()) != 3 {
		t.Error("the refused start left a flow or a job")
	}
}

func TestResendAndVerifySpendTheIPAndAddressBudgets(t *testing.T) {
	p, err := quota.NewProfile(map[quota.Scope][]quota.Window{
		quota.UnknownSendIP:      {{Limit: 2, Per: time.Hour}},
		quota.UnknownVerifyEmail: {{Limit: 1, Per: time.Hour}},
	})
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, withQuota(p))
	ip := netip.MustParseAddr("192.0.2.1")

	res := e.startFrom("alice@example.test", "", ip.String())
	flowID, binding := res.FlowID.String(), res.NewBindingSecret
	e.clock.Advance(policy.ResendPause)
	resend := func() emailauth.ResendResult {
		r, err := e.resend.Execute(context.Background(), emailauth.ResendCommand{FlowID: flowID, BindingSecret: binding, ClientIP: ip})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := resend(); r.Outcome != emailauth.OutcomeOK {
		t.Fatalf("resend = %+v", r)
	}
	e.clock.Advance(policy.ResendPause)
	if r := resend(); r.Outcome != emailauth.OutcomeRateLimited || r.Reason != emailauth.ReasonQuota {
		t.Errorf("a third send from one IP = %+v", r)
	}

	wrong := otherCode(e.code(flowID))
	if r := e.check(flowID, wrong, binding); r.Reason != emailauth.ReasonWrongCode {
		t.Fatalf("first verify = %+v", r)
	}
	if r := e.check(flowID, wrong, binding); r.Outcome != emailauth.OutcomeRateLimited {
		t.Errorf("second verify of the address = %+v, want rate limited", r)
	}
}

// Exhausting the unknown clients' budgets leaves the recognized owner able to sign in.
func TestUnknownClientsExhaustingTheAddressDoNotBlockTheRecognizedOwner(t *testing.T) {
	e := newEnv(t, withQuota(quota.DefaultProfile()))
	const email = "alice@example.test"

	flowID, binding := e.begin(email)
	if res := e.check(flowID, e.code(flowID), binding); res.Outcome != emailauth.OutcomeOK {
		t.Fatalf("first login = %+v", res)
	}

	// An attacker burns the shared budget of unknown clients from many addresses.
	limited := false
	for i := 0; i < 20; i++ {
		ip := netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)}).String()
		if res := e.startFrom(email, "", ip); res.Outcome == emailauth.OutcomeRateLimited {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("the unknown clients were never limited")
	}
	if res := e.startFrom(email, "", "203.0.113.9"); res.Outcome != emailauth.OutcomeRateLimited {
		t.Fatalf("a new unknown client got through: %+v", res)
	}

	// The owner starts from the device that proved the address, and signs in.
	e.clock.Advance(time.Minute)
	owner := e.startFrom(email, binding, "203.0.113.9")
	if owner.Outcome != emailauth.OutcomeOK {
		t.Fatalf("the owner's start = %+v", owner)
	}
	f := e.flow(owner.FlowID.String())
	if f.QuotaClass() != authflow.QuotaRecognized {
		t.Fatalf("the owner's flow class = %s", f.QuotaClass())
	}
	if res := e.check(owner.FlowID.String(), e.code(owner.FlowID.String()), binding); res.Outcome != emailauth.OutcomeOK {
		t.Errorf("the owner's verify = %+v", res)
	}
}

func TestARecognizedFlowIsRefusedWhenItsRecognitionWasRevoked(t *testing.T) {
	e := newEnv(t, withQuota(quota.DefaultProfile()))
	const email = "alice@example.test"
	flowID, binding := e.begin(email)
	login := e.check(flowID, e.code(flowID), binding)
	if login.Outcome != emailauth.OutcomeOK {
		t.Fatalf("login = %+v", login)
	}

	e.clock.Advance(time.Minute)
	second := e.startFrom(email, binding, "")
	id := second.FlowID.String()
	if second.Outcome != emailauth.OutcomeOK || e.flow(id).QuotaClass() != authflow.QuotaRecognized {
		t.Fatalf("start = %+v", second)
	}

	flowBinding := e.flow(id).BindingHash() // read before the transaction: the store is not re-entrant
	err := e.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		return st.Recognized.Revoke(ctx, login.User.ID(), flowBinding, e.clock.Now())
	})
	if err != nil {
		t.Fatal(err)
	}
	spentBefore, jobsBefore := e.store.Spent(port.SpendVerify, e.email(email)), len(e.store.OutboxJobs())

	if res := e.check(id, e.code(id), binding); res.Outcome != emailauth.OutcomeDenied || res.Reason != emailauth.ReasonRecognitionLost {
		t.Errorf("verify after the revocation = %+v", res)
	}
	e.clock.Advance(policy.ResendPause)
	r, err := e.resend.Execute(context.Background(), emailauth.ResendCommand{FlowID: id, BindingSecret: binding})
	if err != nil || r.Outcome != emailauth.OutcomeDenied || r.Reason != emailauth.ReasonRecognitionLost {
		t.Errorf("resend after the revocation = %+v, %v", r, err)
	}
	if e.flow(id).Attempts() != 0 || e.store.Spent(port.SpendVerify, e.email(email)) != spentBefore || len(e.store.OutboxJobs()) != jobsBefore {
		t.Error("a refused request spent an attempt, a quota or queued a mail")
	}

	// A new flow of the same device is an unknown client's, as the document says.
	e.clock.Advance(time.Minute)
	third := e.startFrom(email, binding, "")
	if third.Outcome != emailauth.OutcomeOK || e.flow(third.FlowID.String()).QuotaClass() != authflow.QuotaUnknown {
		t.Errorf("start after the revocation = %+v", third)
	}
}

// Confirming another flow does not raise the class of a flow already started as unknown.
func TestConfirmingAnotherFlowDoesNotRaiseTheQuotaOfAnUnknownFlow(t *testing.T) {
	p, err := quota.NewProfile(map[quota.Scope][]quota.Window{quota.UnknownVerifyEmail: {{Limit: 3, Per: 24 * time.Hour}}})
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, withQuota(p))
	const email = "alice@example.test"

	// Two unknown clients start flows for the same address.
	owner, ownerBinding := e.begin(email)
	other, otherBinding := e.begin(email)

	// The owner's flow is confirmed: the owner's device becomes recognized.
	if res := e.check(owner, e.code(owner), ownerBinding); res.Outcome != emailauth.OutcomeOK {
		t.Fatalf("owner's verify = %+v", res)
	}
	if _, err := e.activeRecognized(email, ownerBinding); err != nil {
		t.Fatalf("the owner's device is not recognized: %v", err)
	}

	// The other flow keeps its class and its budget: the shared budget of unknown clients (3 a
	// day, one already spent by the owner's verify) runs out for it, though a recognized
	// record of the address now exists.
	wrong := otherCode(e.code(other))
	for i, want := range []emailauth.Outcome{emailauth.OutcomeDenied, emailauth.OutcomeDenied, emailauth.OutcomeRateLimited} {
		if res := e.check(other, wrong, otherBinding); res.Outcome != want {
			t.Fatalf("attempt %d = %+v, want %s", i+1, res, want)
		}
	}
	if got := e.flow(other).QuotaClass(); got != authflow.QuotaUnknown {
		t.Errorf("the flow's class became %s", got)
	}
}
