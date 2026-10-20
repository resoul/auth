package emailauth_test

import (
	"context"
	"testing"
	"time"

	"go.airlance.org/auth/internal/application/emailauth"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
)

// inviteOnly is the same use cases, in the invite-only mode.
type inviteOnly struct {
	*env
	start  *emailauth.Start
	resend *emailauth.Resend
	verify *emailauth.VerifyCode
}

func newInviteOnly(t *testing.T, mode identity.RegistrationMode) *inviteOnly {
	t.Helper()
	e := newEnv(t)
	i := &inviteOnly{env: e}

	var err error

	i.start, err = emailauth.NewStart(emailauth.StartDeps{
		UnitOfWork: e.faults, Clock: e.clock, FlowIDs: e.ids, OTP: e.otp, Bindings: e.bindings, Policy: policy, Registration: mode,
	})
	if err != nil {
		t.Fatal(err)
	}

	i.resend, err = emailauth.NewResend(emailauth.ResendDeps{
		UnitOfWork: e.faults, Clock: e.clock, OTP: e.otp, Bindings: e.bindings, Policy: policy, Registration: mode,
	})
	if err != nil {
		t.Fatal(err)
	}

	deps := e.verifyDeps(e.otp)
	deps.Registration = mode

	i.verify, err = emailauth.NewVerifyCode(deps)
	if err != nil {
		t.Fatal(err)
	}

	return i
}

func (i *inviteOnly) invite(raw string, ttl time.Duration) {
	i.t.Helper()

	inv, err := identity.NewInvitation(i.email(raw), i.clock.Now(), ttl)
	if err != nil {
		i.t.Fatal(err)
	}

	i.do(func(ctx context.Context, st port.Stores) error { return st.Invitations.Save(ctx, inv) })
}

func (i *inviteOnly) do(fn func(ctx context.Context, st port.Stores) error) {
	i.t.Helper()

	if err := i.store.Do(context.Background(), fn); err != nil {
		i.t.Fatal(err)
	}
}

func (i *inviteOnly) hasInvitation(raw string) bool {
	i.t.Helper()

	found := false

	i.do(func(ctx context.Context, st port.Stores) error {
		_, err := st.Invitations.FindActive(ctx, i.email(raw), i.clock.Now())
		found = err == nil

		return nil
	})

	return found
}

func (i *inviteOnly) register(raw string) {
	i.t.Helper()
	i.do(func(ctx context.Context, st port.Stores) error {
		user, err := identity.NewUser(mustUserID(i.t, i.ids), i.email(raw), i.clock.Now())
		if err != nil {
			return err
		}

		_, _, err = st.Users.Ensure(ctx, user)

		return err
	})
}

func mustUserID(t *testing.T, ids interface {
	NewUserID() (identity.UserID, error)
}) identity.UserID {
	t.Helper()

	id, err := ids.NewUserID()
	if err != nil {
		t.Fatal(err)
	}

	return id
}

func (i *inviteOnly) begin(raw string) (res emailauth.StartResult, binding string) {
	i.t.Helper()

	res, err := i.start.Execute(context.Background(), emailauth.StartCommand{Email: raw})
	if err != nil || res.Outcome != emailauth.OutcomeOK {
		i.t.Fatalf("start %q = %+v, %v", raw, res, err)
	}

	return res, res.NewBindingSecret
}

func (i *inviteOnly) check(flowID, code, binding string) emailauth.VerifyCodeResult {
	i.t.Helper()

	res, err := i.verify.Execute(context.Background(), emailauth.VerifyCodeCommand{FlowID: flowID, Code: code, BindingSecret: binding})
	if err != nil {
		i.t.Fatalf("verify: %v", err)
	}

	return res
}

func TestInviteOnlyStartSendsMailOnlyToTheInvitedAndTheRegistered(t *testing.T) {
	i := newInviteOnly(t, identity.RegistrationInviteOnly)
	i.invite("invited@example.test", 24*time.Hour)
	i.register("member@example.test")
	i.invite("lapsed@example.test", time.Hour)
	i.clock.Advance(2 * time.Hour)

	cases := map[string]bool{
		"invited@example.test":  true,
		"member@example.test":   true,
		"stranger@example.test": false,
		"lapsed@example.test":   false,
	}
	jobs := 0

	for raw, mailed := range cases {
		res, _ := i.begin(raw)

		if mailed {
			jobs++
		}

		if got := res.Reason == emailauth.ReasonNotInvited; got == mailed {
			t.Errorf("%s: reason %q, mailed %v", raw, res.Reason, mailed)
		}

		if got := len(i.store.OutboxJobs()); got != jobs {
			t.Fatalf("after %s: %d jobs, want %d", raw, got, jobs)
		}
	}
}

func TestAnUninvitedStartLooksLikeAnyOtherAndSpendsTheSameQuota(t *testing.T) {
	i := newInviteOnly(t, identity.RegistrationInviteOnly)
	i.invite("invited@example.test", 24*time.Hour)

	invited, _ := i.begin("invited@example.test")
	stranger, _ := i.begin("stranger@example.test")

	// Everything the client can see has the same shape; the flow exists either way.
	if !invited.ExpiresAt.Equal(stranger.ExpiresAt) || !invited.ResendAfter.Equal(stranger.ResendAfter) || stranger.FlowID.IsZero() || stranger.NewBindingSecret == "" {
		t.Errorf("invited = %+v, stranger = %+v", invited, stranger)
	}

	if i.flow(stranger.FlowID.String()).Attempts() != 0 {
		t.Error("the flow of a stranger is not an ordinary fresh flow")
	}

	for _, raw := range []string{"invited@example.test", "stranger@example.test"} {
		if got := i.store.Spent(port.SpendSend, i.email(raw)); got != 1 {
			t.Errorf("%s spent %d send budgets, want 1", raw, got)
		}
	}
}

func TestOpenModeSendsToEveryone(t *testing.T) {
	for _, mode := range []identity.RegistrationMode{identity.RegistrationOpen, ""} {
		i := newInviteOnly(t, mode)

		res, _ := i.begin("stranger@example.test")
		if res.Reason != "" || len(i.store.OutboxJobs()) != 1 {
			t.Errorf("mode %q: reason %q, %d jobs", mode, res.Reason, len(i.store.OutboxJobs()))
		}
	}
}

func TestInviteOnlyResendSendsMailOnlyWhereStartWould(t *testing.T) {
	i := newInviteOnly(t, identity.RegistrationInviteOnly)
	i.invite("invited@example.test", 24*time.Hour)
	a, aBinding := i.begin("invited@example.test")
	b, bBinding := i.begin("stranger@example.test")
	i.clock.Advance(2 * time.Minute)

	for _, tc := range []struct {
		flow, binding string
		mailed        bool
	}{{a.FlowID.String(), aBinding, true}, {b.FlowID.String(), bBinding, false}} {
		before := len(i.store.OutboxJobs())

		res, err := i.resend.Execute(context.Background(), emailauth.ResendCommand{FlowID: tc.flow, BindingSecret: tc.binding})
		if err != nil || res.Outcome != emailauth.OutcomeOK {
			t.Fatalf("resend = %+v, %v", res, err)
		}

		if got := len(i.store.OutboxJobs()) - before; (got == 1) != tc.mailed || got > 1 {
			t.Errorf("flow %s: %d new jobs, mailed = %v", tc.flow, got, tc.mailed)
		}

		if (res.Reason == emailauth.ReasonNotInvited) == tc.mailed {
			t.Errorf("flow %s: reason %q", tc.flow, res.Reason)
		}
	}
}

func TestVerifyCreatesTheAccountOfAnInvitedAddressAndUsesTheInvitationUp(t *testing.T) {
	i := newInviteOnly(t, identity.RegistrationInviteOnly)
	i.invite("invited@example.test", 24*time.Hour)
	res, binding := i.begin("invited@example.test")
	flowID := res.FlowID.String()

	got := i.check(flowID, i.code(flowID), binding)
	if got.Outcome != emailauth.OutcomeOK || !got.UserCreated || got.Next != emailauth.NextEnrollPasskey {
		t.Fatalf("verify = %+v", got)
	}

	if i.hasInvitation("invited@example.test") {
		t.Error("the invitation outlived the registration")
	}

	if _, ok := i.store.User(i.email("invited@example.test")); !ok {
		t.Error("the account was not created")
	}

	var used *port.AuditEvent

	events := i.store.AuditEvents()
	for k := range events {
		if events[k].Type == port.AuditInvitationUsed {
			used = &events[k]
		}
	}

	if used == nil || used.UserID != got.User.ID() || len(used.Fields) != 0 {
		t.Errorf("invitation.used event = %+v", used)
	}

	// The next sign-in of the same address needs no invitation: the account exists now.
	again, againBinding := i.begin("invited@example.test")
	if again.Reason != "" {
		t.Errorf("a registered address was refused: %q", again.Reason)
	}

	if next := i.check(again.FlowID.String(), i.code(again.FlowID.String()), againBinding); next.Outcome != emailauth.OutcomeOK || next.UserCreated {
		t.Errorf("second sign-in = %+v", next)
	}
}

func TestVerifyRefusesANewAccountWhenTheInvitationWentAwayMeanwhile(t *testing.T) {
	i := newInviteOnly(t, identity.RegistrationInviteOnly)
	i.invite("invited@example.test", 24*time.Hour)
	res, binding := i.begin("invited@example.test")
	flowID := res.FlowID.String()
	code := i.code(flowID)
	// The operator withdraws the invitation after the mail went out.
	i.do(func(ctx context.Context, st port.Stores) error {
		_, err := st.Invitations.Delete(ctx, i.email("invited@example.test"))
		return err
	})

	got := i.check(flowID, code, binding)
	if got.Outcome != emailauth.OutcomeDenied || got.Reason != emailauth.ReasonNotInvited {
		t.Fatalf("verify = %+v, want denied: not invited", got)
	}

	if _, ok := i.store.User(i.email("invited@example.test")); ok {
		t.Error("an account was created without an invitation")
	}

	if i.flow(flowID).Attempts() != 1 {
		t.Error("the refused check did not spend its attempt")
	}
	// The refusal is the one every refusal of the proof has: nothing tells it from a wrong code.
	wrong := i.check(flowID, otherCode(code), binding)
	if wrong.Outcome != got.Outcome {
		t.Errorf("a wrong code is %v, a missing invitation %v", wrong.Outcome, got.Outcome)
	}
}

func TestAnExistingUserSignsInWithoutAnInvitationAndLeavesOthersAlone(t *testing.T) {
	i := newInviteOnly(t, identity.RegistrationInviteOnly)
	i.register("member@example.test")
	// An old invitation for the same address is not what lets the member in, and is not spent by it.
	i.invite("member@example.test", 24*time.Hour)
	res, binding := i.begin("member@example.test")

	got := i.check(res.FlowID.String(), i.code(res.FlowID.String()), binding)
	if got.Outcome != emailauth.OutcomeOK || got.UserCreated {
		t.Fatalf("verify = %+v", got)
	}

	if !i.hasInvitation("member@example.test") {
		t.Error("signing in used up an invitation that registering would have used")
	}
}

func TestOneInvitationRegistersOneAccountEvenWithTwoFlowsOpen(t *testing.T) {
	i := newInviteOnly(t, identity.RegistrationInviteOnly)
	i.invite("invited@example.test", 24*time.Hour)
	first, firstBinding := i.begin("invited@example.test")
	second, secondBinding := i.begin("invited@example.test")

	a := i.check(first.FlowID.String(), i.code(first.FlowID.String()), firstBinding)
	b := i.check(second.FlowID.String(), i.code(second.FlowID.String()), secondBinding)

	if a.Outcome != emailauth.OutcomeOK || !a.UserCreated {
		t.Fatalf("first = %+v", a)
	}
	// The second proof is of the same mailbox, whose account exists now: it is a sign-in, not a registration.
	if b.Outcome != emailauth.OutcomeOK || b.UserCreated || b.User.ID() != a.User.ID() {
		t.Errorf("second = %+v, want a sign-in of the same account", b)
	}

	if i.store.UserCount() != 1 {
		t.Errorf("%d accounts", i.store.UserCount())
	}
}

func TestAFailedRegistrationKeepsTheInvitation(t *testing.T) {
	i := newInviteOnly(t, identity.RegistrationInviteOnly)
	i.invite("invited@example.test", 24*time.Hour)
	res, binding := i.begin("invited@example.test")
	flowID := res.FlowID.String()
	code := i.code(flowID)
	i.faults.wrap = func(s port.Stores) port.Stores { s.Users = failingUsers{s.Users}; return s }

	if _, err := i.verify.Execute(context.Background(), emailauth.VerifyCodeCommand{FlowID: flowID, Code: code, BindingSecret: binding}); err == nil {
		t.Fatal("verify did not fail")
	}

	if !i.hasInvitation("invited@example.test") {
		t.Error("a registration that rolled back used the invitation up")
	}

	i.faults.wrap = nil
	if got := i.check(flowID, code, binding); got.Outcome != emailauth.OutcomeOK || !got.UserCreated {
		t.Errorf("the retry = %+v", got)
	}
}

// block bars the registered address, as an operator does.
func (i *inviteOnly) block(raw string) {
	i.t.Helper()
	i.do(func(ctx context.Context, st port.Stores) error {
		u, err := st.Users.FindByEmail(ctx, i.email(raw))
		if err != nil {
			return err
		}

		if err := u.Block(i.clock.Now()); err != nil {
			return err
		}

		return st.Users.SetBlocked(ctx, u)
	})
}

func TestABlockedAddressGetsNoCodeInAnyMode(t *testing.T) {
	for _, mode := range []identity.RegistrationMode{identity.RegistrationOpen, identity.RegistrationInviteOnly} {
		i := newInviteOnly(t, mode)
		i.register("blocked@example.test")
		i.register("member@example.test")
		i.block("blocked@example.test")

		blocked, _ := i.begin("blocked@example.test")

		member, _ := i.begin("member@example.test")
		if blocked.Reason != emailauth.ReasonBlocked || member.Reason != "" {
			t.Errorf("%s: reasons %q and %q", mode, blocked.Reason, member.Reason)
		}

		if got := len(i.store.OutboxJobs()); got != 1 {
			t.Errorf("%s: %d mails queued, want 1 (only the member)", mode, got)
		}
		// Nothing the client can see tells the two apart, and the quota is spent alike.
		if !blocked.ExpiresAt.Equal(member.ExpiresAt) || !blocked.ResendAfter.Equal(member.ResendAfter) || blocked.FlowID.IsZero() || blocked.NewBindingSecret == "" {
			t.Errorf("%s: blocked = %+v, member = %+v", mode, blocked, member)
		}

		for _, raw := range []string{"blocked@example.test", "member@example.test"} {
			if got := i.store.Spent(port.SpendSend, i.email(raw)); got != 1 {
				t.Errorf("%s: %s spent %d send budgets, want 1", mode, raw, got)
			}
		}

		// A block that comes after the flow started also stops the resend.
		i.clock.Advance(2 * time.Minute)
		i.block("member@example.test")

		res, err := i.resend.Execute(context.Background(), emailauth.ResendCommand{FlowID: member.FlowID.String(), BindingSecret: member.NewBindingSecret})
		if err != nil || res.Outcome != emailauth.OutcomeOK || res.Reason != emailauth.ReasonBlocked {
			t.Errorf("%s: resend after the block = %+v, %v", mode, res, err)
		}

		if got := len(i.store.OutboxJobs()); got != 1 {
			t.Errorf("%s: a resend mailed a blocked address (%d jobs)", mode, got)
		}
	}
}
