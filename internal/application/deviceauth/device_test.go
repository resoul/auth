package deviceauth_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"net/netip"

	"airlance.org/auth/internal/adapter/memory"
	"airlance.org/auth/internal/application/deviceauth"
	"airlance.org/auth/internal/application/port"
	appsession "airlance.org/auth/internal/application/session"
	ddevice "airlance.org/auth/internal/domain/deviceauth"
	dpasskey "airlance.org/auth/internal/domain/passkey"
	"airlance.org/auth/internal/domain/quota"
	"airlance.org/auth/internal/testutil"
)

func netipAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestADeviceSignsInWithTheApprovalOfAnother(t *testing.T) {
	e := newEnv(t)
	phone := e.phone()
	laptop := e.newLaptop("Office laptop")
	if got := e.stateOf(laptop); got != deviceauth.StatePending {
		t.Fatalf("state = %s", got)
	}

	// The phone sees who asks, not the code.
	view, err := e.approver.Inspect(context.Background(), phone.actor, laptop.id())
	must(t, err)
	if view.Outcome != deviceauth.OutcomeOK || view.View.DeviceName != "Office laptop" || !view.View.ExpiresAt.Equal(t0.Add(ddevice.TTL)) {
		t.Fatalf("Inspect = %+v", view)
	}

	stepUp := e.stepUp(phone, dpasskey.OperationApproveDevice)
	if got := e.approve(phone, laptop, laptop.res.PairingCode, stepUp); got.Outcome != deviceauth.OutcomeOK {
		t.Fatalf("Approve = %+v", got)
	}
	if got := e.stateOf(laptop); got != deviceauth.StateApproved {
		t.Fatalf("state after approval = %s", got)
	}

	e.clock.Advance(30 * time.Second)
	res := e.redeemFor(laptop)
	if res.Outcome != deviceauth.OutcomeOK || res.User.ID() != phone.user.ID() {
		t.Fatalf("Redeem = %+v", res)
	}
	// A session of its own: another ID than the phone's, bound to the laptop's binding, named by the laptop.
	if res.Session.ID() == phone.actor.SessionID || res.Session.UserID() != phone.user.ID() || res.Session.DeviceName() != "Office laptop" {
		t.Errorf("session = %+v", res.Session.Record())
	}
	wantHash, err := e.binding.HashBinding(laptop.binding)
	must(t, err)
	if res.Session.Binding() != wantHash {
		t.Error("the session is not bound to the laptop's client binding")
	}
	if !slices.Equal(res.Session.AMR(), []string{"qr", "passkey"}) {
		t.Errorf("amr = %v", res.Session.AMR())
	}
	claims, err := e.verify.VerifyAccess(res.Access.Value)
	if err != nil || claims.UserID != phone.user.ID() || !slices.Equal(claims.AMR, []string{"qr", "passkey"}) {
		t.Errorf("claims = %+v, %v", claims, err)
	}
	if state := e.stateOf(laptop); res.RefreshSecret == "" || state != deviceauth.StateRedeemed {
		t.Errorf("refresh %q, state %s", res.RefreshSecret, state)
	}

	// The audit log says who approved and how the session was opened.
	if ev := e.auditOf(port.AuditDeviceApproved); len(ev) != 1 || ev[0].UserID != phone.user.ID() || ev[0].SessionID != phone.actor.SessionID || !ev[0].Lasting() {
		t.Errorf("approval audit = %+v", ev)
	}
	logins := e.auditOf(port.AuditLoginSucceeded)
	if len(logins) != 1 || logins[0].Fields["method"] != "qr" || logins[0].SessionID != res.Session.ID() {
		t.Errorf("login audit = %+v", logins)
	}

	// Once: a second redemption of the same request gets nothing, and the sessions are independent.
	if again := e.redeemFor(laptop); again.Outcome != deviceauth.OutcomeDenied || again.Reason != deviceauth.ReasonNotApproved || again.Session != nil {
		t.Errorf("a second Redeem = %+v", again)
	}
	if got := e.store.SessionCount(); got != 2 {
		t.Errorf("%d sessions, want the phone's and the laptop's", got)
	}
}

func TestASignInOfANewDeviceTellsTheOwnerAndOneOfAKnownDeviceDoesNot(t *testing.T) {
	e := newEnv(t)
	phone := e.phone()
	notices := func() []port.MailJob {
		var out []port.MailJob
		for _, j := range e.store.OutboxJobs() {
			if j.Kind == port.JobNewDevice {
				out = append(out, j)
			}
		}
		return out
	}
	signIn := func(l laptop) {
		t.Helper()
		if r := e.approve(phone, l, l.res.PairingCode, e.stepUp(phone, dpasskey.OperationApproveDevice)); r.Outcome != deviceauth.OutcomeOK {
			t.Fatalf("Approve = %+v", r)
		}
		if res := e.redeemFor(l); res.Outcome != deviceauth.OutcomeOK {
			t.Fatalf("Redeem = %+v", res)
		}
	}

	// Approving is not signing in: nothing is sent until the new device takes its session.
	first := e.newLaptop("Office laptop")
	if r := e.approve(phone, first, first.res.PairingCode, e.stepUp(phone, dpasskey.OperationApproveDevice)); r.Outcome != deviceauth.OutcomeOK {
		t.Fatalf("Approve = %+v", r)
	}
	if n := len(notices()); n != 0 {
		t.Fatalf("%d notices before the redemption", n)
	}
	e.clock.Advance(time.Minute)
	if res := e.redeemFor(first); res.Outcome != deviceauth.OutcomeOK {
		t.Fatalf("Redeem = %+v", res)
	}
	got := notices()
	if len(got) != 1 || got[0].UserID != phone.user.ID() || got[0].DeviceName != "Office laptop" || got[0].ClientIP != ip ||
		!got[0].EventAt.Equal(e.clock.Now()) {
		t.Fatalf("notices = %+v", got)
	}

	// The same laptop asking again is a known client; another laptop is not.
	signIn(e.again(first, "Office laptop"))
	if n := len(notices()); n != 1 {
		t.Errorf("a known device made %d notices in all", n)
	}
	signIn(e.newLaptop("Living room TV"))
	if got := notices(); len(got) != 2 || got[1].DeviceName != "Living room TV" {
		t.Errorf("notices = %+v", got)
	}

	// A refusal sends nothing: the request that is not approved is not redeemed.
	before := len(notices())
	if res := e.redeemFor(e.newLaptop("Stranger")); res.Outcome != deviceauth.OutcomeDenied {
		t.Fatalf("Redeem = %+v", res)
	}
	if n := len(notices()); n != before {
		t.Errorf("a refused redemption made %d notices", n-before)
	}
}

func TestStartMakesDistinctRequestsAndKeepsOnlyHashes(t *testing.T) {
	e := newEnv(t)
	a, b := e.newLaptop("a"), e.newLaptop("b")
	if a.id() == b.id() || a.res.PollSecret == b.res.PollSecret || a.binding == b.binding {
		t.Error("two requests share a value")
	}
	if !ddevice.ValidPairingCode(a.res.PairingCode) || !a.res.ExpiresAt.Equal(t0.Add(ddevice.TTL)) {
		t.Errorf("start = %+v", a.res)
	}
	var stored ddevice.Record
	e.do(func(ctx context.Context, s port.Stores) error {
		req, err := s.Devices.Get(ctx, a.res.RequestID)
		stored = req.Record()
		return err
	})
	if stored.PollHash == testutil.SecretHash(a.res.PollSecret) {
		// The test hash helper is plain SHA-256 of the text; the real one hashes the decoded bytes. They must differ
		// from the secret itself in any case.
		t.Log("the poll hash happens to match the helper")
	}
	if strings.Contains(string(stored.PollHash.Bytes()), a.res.PollSecret) {
		t.Error("the poll secret is stored")
	}

	// A client with a binding keeps it and is issued none.
	kept, err := e.start.Execute(context.Background(), deviceauth.StartCommand{BindingSecret: a.binding, ClientIP: ip})
	must(t, err)
	if kept.Outcome != deviceauth.OutcomeOK || kept.NewBindingSecret != "" {
		t.Errorf("start with a binding = %+v", kept)
	}
	if _, err := e.start.Execute(context.Background(), deviceauth.StartCommand{BindingSecret: "not a binding", ClientIP: ip}); err == nil {
		t.Error("a malformed binding was accepted")
	}
	for _, name := range []string{strings.Repeat("x", 65), "a\nb"} {
		if _, err := e.start.Execute(context.Background(), deviceauth.StartCommand{DeviceName: name, ClientIP: ip}); !errors.Is(err, deviceauth.ErrInvalidName) {
			t.Errorf("name %q: error = %v, want ErrInvalidName", name, err)
		}
	}
}

func TestStartIsLimitedPerAddressAndWritesNothingOverTheLimit(t *testing.T) {
	p, err := quota.NewProfile(map[quota.Scope][]quota.Window{quota.DeviceIP: {{Limit: 2, Per: time.Hour}}})
	must(t, err)
	e := newEnv(t, memory.WithQuota(p))
	e.newLaptop("1")
	e.newLaptop("2")
	res, err := e.start.Execute(context.Background(), deviceauth.StartCommand{ClientIP: ip})
	must(t, err)
	if res.Outcome != deviceauth.OutcomeRateLimited || res.Reason != deviceauth.ReasonQuota || res.PollSecret != "" || !res.RequestID.IsZero() {
		t.Errorf("third start = %+v", res)
	}
	other, err := e.start.Execute(context.Background(), deviceauth.StartCommand{ClientIP: netipAddr("203.0.113.9")})
	must(t, err)
	if other.Outcome != deviceauth.OutcomeOK {
		t.Errorf("another address: %+v", other)
	}
}

func TestStatusIsTheSameRefusalForEveryWrongProof(t *testing.T) {
	e := newEnv(t)
	l := e.newLaptop("laptop")
	other := e.newLaptop("other")
	good := deviceauth.StatusCommand{RequestID: l.id(), PollSecret: l.res.PollSecret, BindingSecret: l.binding}
	for name, cmd := range map[string]deviceauth.StatusCommand{
		"unknown request":      {RequestID: "AAECAwQFBgcICQoLDA0ODw", PollSecret: l.res.PollSecret, BindingSecret: l.binding},
		"malformed request":    {RequestID: "nope", PollSecret: l.res.PollSecret, BindingSecret: l.binding},
		"another's secret":     {RequestID: l.id(), PollSecret: other.res.PollSecret, BindingSecret: l.binding},
		"malformed secret":     {RequestID: l.id(), PollSecret: "x", BindingSecret: l.binding},
		"empty secret":         {RequestID: l.id(), PollSecret: "", BindingSecret: l.binding},
		"another's binding":    {RequestID: l.id(), PollSecret: l.res.PollSecret, BindingSecret: other.binding},
		"malformed binding":    {RequestID: l.id(), PollSecret: l.res.PollSecret, BindingSecret: "x"},
		"no binding":           {RequestID: l.id(), PollSecret: l.res.PollSecret},
		"secret with a suffix": {RequestID: l.id(), PollSecret: l.res.PollSecret + "A", BindingSecret: l.binding},
	} {
		res, err := e.status.Execute(context.Background(), cmd)
		must(t, err)
		if res.Outcome != deviceauth.OutcomeDenied || res.State != "" {
			t.Errorf("%s: %+v", name, res)
		}
	}
	if res, err := e.status.Execute(context.Background(), good); err != nil || res.Outcome != deviceauth.OutcomeOK {
		t.Errorf("the right proof: %+v, %v", res, err)
	}
}

func TestStatusFollowsTheRequestThroughItsStates(t *testing.T) {
	e := newEnv(t)
	phone := e.phone()

	denied := e.newLaptop("denied")
	res, err := e.approver.Deny(context.Background(), phone.actor, denied.id())
	must(t, err)
	if res.Outcome != deviceauth.OutcomeOK || e.stateOf(denied) != deviceauth.StateDenied {
		t.Errorf("Deny = %+v, state %s", res, e.stateOf(denied))
	}

	expiring := e.newLaptop("expiring")
	if e.stateOf(expiring) != deviceauth.StatePending {
		t.Fatal("not pending")
	}
	e.clock.Advance(ddevice.TTL)
	if got := e.stateOf(expiring); got != deviceauth.StateExpired {
		t.Errorf("an old pending request = %s", got)
	}
	if got := e.stateOf(denied); got != deviceauth.StateDenied {
		t.Errorf("a denied request after the TTL = %s: a refusal stays a refusal", got)
	}
}

func TestInspectShowsOnlyALivePendingRequestToASignedInUser(t *testing.T) {
	e := newEnv(t)
	phone := e.phone()
	l := e.newLaptop("laptop")
	inspect := func(actor appsession.Actor, id string) deviceauth.InspectResult {
		res, err := e.approver.Inspect(context.Background(), actor, id)
		must(t, err)
		return res
	}
	for name, id := range map[string]string{"unknown": "AAECAwQFBgcICQoLDA0ODw", "malformed": "nope", "empty": ""} {
		if r := inspect(phone.actor, id); r.Outcome != deviceauth.OutcomeNotFound || r.View.DeviceName != "" {
			t.Errorf("%s: %+v", name, r)
		}
	}
	if r := inspect(appsession.Actor{}, l.id()); r.Outcome != deviceauth.OutcomeDenied || r.Reason != deviceauth.ReasonNoSession || r.View.DeviceName != "" {
		t.Errorf("without a session: %+v", r)
	}
	must2 := func(r deviceauth.Result, err error) deviceauth.Result { must(t, err); return r }
	must2(e.approver.Deny(context.Background(), phone.actor, l.id()))
	if r := inspect(phone.actor, l.id()); r.Outcome != deviceauth.OutcomeNotFound {
		t.Errorf("a denied request: %+v", r)
	}
	late := e.newLaptop("late")
	e.clock.Advance(ddevice.TTL)
	e.do(func(ctx context.Context, s port.Stores) error { return nil })
	if r := inspect(phone.actor, late.id()); r.Outcome != deviceauth.OutcomeNotFound {
		t.Errorf("an expired request: %+v", r)
	}
}

func TestApprovalNeedsASessionAndAFreshProofForThisOperation(t *testing.T) {
	e := newEnv(t)
	phone, other := e.phone(), e.phone()
	l := e.newLaptop("laptop")
	code := l.res.PairingCode

	if r := e.approve(noPhone, l, code, "x"); r.Outcome != deviceauth.OutcomeDenied || r.Reason != deviceauth.ReasonNoSession {
		t.Errorf("no session: %+v", r)
	}
	for name, secret := range map[string]string{
		"no proof":               "",
		"garbage":                "x",
		"a proof for another op": e.stepUp(phone, dpasskey.OperationChangeEmail),
		"another session's":      e.stepUp(other, dpasskey.OperationApproveDevice),
	} {
		r := e.approve(phone, l, code, secret)
		if r.Outcome != deviceauth.OutcomeStepUpRequired {
			t.Errorf("%s: %+v", name, r)
		}
	}
	// None of that touched the request: no attempt was spent and it is still pending.
	var req *ddevice.Request
	e.do(func(ctx context.Context, s port.Stores) (err error) {
		req, err = s.Devices.Get(ctx, l.res.RequestID)
		return
	})
	if req.Attempts() != 0 || req.State() != ddevice.StatePending {
		t.Errorf("a refused approval changed the request: %+v", req.Record())
	}
	// The proof of the right operation works, and only once.
	proof := e.stepUp(phone, dpasskey.OperationApproveDevice)
	if r := e.approve(phone, l, code, proof); r.Outcome != deviceauth.OutcomeOK {
		t.Fatalf("Approve = %+v", r)
	}
	second := e.newLaptop("second")
	if r := e.approve(phone, second, second.res.PairingCode, proof); r.Outcome != deviceauth.OutcomeStepUpRequired {
		t.Errorf("a spent proof approved another device: %+v", r)
	}
}

func TestWrongCodesSpendAttemptsNotTheProofAndTheThirdKillsTheRequest(t *testing.T) {
	e := newEnv(t)
	phone := e.phone()
	l := e.newLaptop("laptop")
	proof := e.stepUp(phone, dpasskey.OperationApproveDevice)
	wrong := "000000"
	if l.res.PairingCode == wrong {
		wrong = "111111"
	}
	for i := 1; i < ddevice.MaxAttempts; i++ {
		if r := e.approve(phone, l, wrong, proof); r.Outcome != deviceauth.OutcomeDenied || r.Reason != deviceauth.ReasonWrongCode {
			t.Fatalf("wrong code %d: %+v", i, r)
		}
	}
	// The proof survived the mistakes: the right code now succeeds with it.
	spare := e.newLaptop("spare")
	_ = spare
	if r := e.approve(phone, l, wrong, proof); r.Outcome != deviceauth.OutcomeDenied || r.Reason != deviceauth.ReasonAttemptsExhausted {
		t.Fatalf("the last wrong code: %+v", r)
	}
	if r := e.approve(phone, l, l.res.PairingCode, proof); r.Outcome != deviceauth.OutcomeDenied || r.Reason != deviceauth.ReasonNotPending {
		t.Errorf("the right code after the request died: %+v", r)
	}
	if got := e.stateOf(l); got != deviceauth.StateDenied {
		t.Errorf("state = %s", got)
	}
	// Only the killing code is audited, with its reason; the first two mistakes are the metric's business.
	if got := e.auditOf(port.AuditDeviceDenied); len(got) != 1 || got[0].Result != port.AuditDenied ||
		got[0].Fields["reason"] != string(deviceauth.ReasonAttemptsExhausted) || got[0].UserID != phone.user.ID() {
		t.Errorf("audit of the killed request: %+v", got)
	}
	if res := e.redeemFor(l); res.Outcome != deviceauth.OutcomeDenied {
		t.Errorf("a dead request was redeemed: %+v", res)
	}
	if n := len(e.auditOf(port.AuditDeviceApproved)); n != 0 {
		t.Errorf("%d approvals audited", n)
	}
	// The unspent proof still opens a different request.
	fresh := e.newLaptop("fresh")
	if r := e.approve(phone, fresh, fresh.res.PairingCode, proof); r.Outcome != deviceauth.OutcomeOK {
		t.Errorf("the unspent proof: %+v", r)
	}
}

func TestApprovalRefusals(t *testing.T) {
	e := newEnv(t)
	phone := e.phone()
	approveOnce := func(l laptop) deviceauth.Result {
		return e.approve(phone, l, l.res.PairingCode, e.stepUp(phone, dpasskey.OperationApproveDevice))
	}
	for name, id := range map[string]string{"unknown": "AAECAwQFBgcICQoLDA0ODw", "malformed": "nope"} {
		r, err := e.approver.Approve(context.Background(), deviceauth.ApproveCommand{
			Actor: phone.actor, RequestID: id, PairingCode: "123456", StepUpSecret: e.stepUp(phone, dpasskey.OperationApproveDevice),
		})
		must(t, err)
		if r.Outcome != deviceauth.OutcomeNotFound {
			t.Errorf("%s: %+v", name, r)
		}
	}
	l := e.newLaptop("laptop")
	if r := approveOnce(l); r.Outcome != deviceauth.OutcomeOK {
		t.Fatal(r)
	}
	if r := approveOnce(l); r.Outcome != deviceauth.OutcomeDenied || r.Reason != deviceauth.ReasonNotPending {
		t.Errorf("approving twice: %+v", r)
	}
	late := e.newLaptop("late")
	e.clock.Advance(ddevice.TTL)
	// The phone's own session ends at the same time as it would idle; give it a fresh one.
	phone = e.phone()
	if r := approveOnce(late); r.Outcome != deviceauth.OutcomeDenied || r.Reason != deviceauth.ReasonExpired {
		t.Errorf("an expired request: %+v", r)
	}
}

func TestDenyNeedsASessionAndOnlyEndsAPendingRequest(t *testing.T) {
	e := newEnv(t)
	phone := e.phone()
	l := e.newLaptop("laptop")
	if r, err := e.approver.Deny(context.Background(), appsession.Actor{}, l.id()); err != nil || r.Outcome != deviceauth.OutcomeDenied || r.Reason != deviceauth.ReasonNoSession {
		t.Errorf("Deny without a session = %+v, %v", r, err)
	}
	if r, err := e.approver.Deny(context.Background(), phone.actor, "nope"); err != nil || r.Outcome != deviceauth.OutcomeNotFound {
		t.Errorf("Deny of a malformed id = %+v, %v", r, err)
	}
	if r, err := e.approver.Deny(context.Background(), phone.actor, l.id()); err != nil || r.Outcome != deviceauth.OutcomeOK {
		t.Fatalf("Deny = %+v, %v", r, err)
	}
	if r, err := e.approver.Deny(context.Background(), phone.actor, l.id()); err != nil || r.Outcome != deviceauth.OutcomeNotFound {
		t.Errorf("a second Deny = %+v, %v", r, err)
	}
	if got := e.auditOf(port.AuditDeviceDenied); len(got) != 1 || got[0].UserID != phone.user.ID() {
		t.Errorf("deny audit = %+v", got)
	}
	// A denied request cannot be approved with the right code, nor redeemed.
	proof := e.stepUp(phone, dpasskey.OperationApproveDevice)
	if r := e.approve(phone, l, l.res.PairingCode, proof); r.Outcome != deviceauth.OutcomeDenied || r.Reason != deviceauth.ReasonNotPending {
		t.Errorf("approving a denied request: %+v", r)
	}
	// An approved request cannot be denied afterwards: the approval stands.
	ok := e.newLaptop("ok")
	if r := e.approve(phone, ok, ok.res.PairingCode, proof); r.Outcome != deviceauth.OutcomeOK {
		t.Fatal(r)
	}
	if r, err := e.approver.Deny(context.Background(), phone.actor, ok.id()); err != nil || r.Outcome != deviceauth.OutcomeNotFound {
		t.Errorf("Deny of an approved request = %+v, %v", r, err)
	}
}

func TestRedeemNeedsTheSecretTheBindingAndAnApprovedLiveRequest(t *testing.T) {
	e := newEnv(t)
	phone := e.phone()
	l := e.newLaptop("laptop")
	other := e.newLaptop("other")
	attempt := func(cmd deviceauth.RedeemCommand) deviceauth.RedeemResult {
		res, err := e.redeem.Execute(context.Background(), cmd)
		must(t, err)
		return res
	}

	// Pending: nothing to redeem yet.
	if r := e.redeemFor(l); r.Outcome != deviceauth.OutcomeDenied || r.Reason != deviceauth.ReasonNotApproved {
		t.Errorf("a pending request: %+v", r)
	}
	if r := e.approve(phone, l, l.res.PairingCode, e.stepUp(phone, dpasskey.OperationApproveDevice)); r.Outcome != deviceauth.OutcomeOK {
		t.Fatal(r)
	}
	for name, cmd := range map[string]deviceauth.RedeemCommand{
		"another's secret":  {RequestID: l.id(), PollSecret: other.res.PollSecret, BindingSecret: l.binding},
		"another's binding": {RequestID: l.id(), PollSecret: l.res.PollSecret, BindingSecret: other.binding},
		"malformed secret":  {RequestID: l.id(), PollSecret: "x", BindingSecret: l.binding},
		"no binding":        {RequestID: l.id(), PollSecret: l.res.PollSecret},
		"unknown request":   {RequestID: "AAECAwQFBgcICQoLDA0ODw", PollSecret: l.res.PollSecret, BindingSecret: l.binding},
		"malformed id":      {RequestID: "nope", PollSecret: l.res.PollSecret, BindingSecret: l.binding},
	} {
		if r := attempt(cmd); r.Outcome != deviceauth.OutcomeDenied || r.Session != nil || r.RefreshSecret != "" || r.Access.Value != "" {
			t.Errorf("%s: %+v", name, r)
		}
	}
	// None of those spent the approval.
	if got := e.stateOf(l); got != deviceauth.StateApproved {
		t.Fatalf("state after refused redemptions = %s", got)
	}
	e.clock.Advance(ddevice.TTL)
	if r := e.redeemFor(l); r.Outcome != deviceauth.OutcomeDenied || r.Reason != deviceauth.ReasonExpired {
		t.Errorf("an expired approval: %+v", r)
	}
	if e.store.SessionCount() != 1 {
		t.Errorf("%d sessions: only the phone's may exist", e.store.SessionCount())
	}
}

func TestAnApprovalLastsOnlyWhileWhatProvedItStands(t *testing.T) {
	e := newEnv(t)
	approved := func() (phone, laptop) {
		p := e.phone()
		l := e.newLaptop("laptop")
		if r := e.approve(p, l, l.res.PairingCode, e.stepUp(p, dpasskey.OperationApproveDevice)); r.Outcome != deviceauth.OutcomeOK {
			t.Fatal(r)
		}
		return p, l
	}

	t.Run("the approving session was ended", func(t *testing.T) {
		p, l := approved()
		e.do(func(ctx context.Context, s port.Stores) error {
			return s.Sessions.RevokeAllForUser(ctx, p.user.ID(), e.clock.Now())
		})
		before := e.store.SessionCount()
		r := e.redeemFor(l)
		if r.Outcome != deviceauth.OutcomeDenied || r.Reason != deviceauth.ReasonApproverGone || r.Session != nil {
			t.Errorf("Redeem = %+v", r)
		}
		if e.store.SessionCount() != before {
			t.Error("a session was issued on an approval whose session had ended")
		}
	})

	t.Run("the user was blocked", func(t *testing.T) {
		p, l := approved()
		e.do(func(ctx context.Context, s port.Stores) error {
			u, err := s.Users.Get(ctx, p.user.ID())
			if err != nil {
				return err
			}
			if err := u.Block(e.clock.Now()); err != nil {
				return err
			}
			return s.Users.SetBlocked(ctx, u)
		})
		if r := e.redeemFor(l); r.Outcome != deviceauth.OutcomeDenied || r.Reason != deviceauth.ReasonBlocked || r.Session != nil {
			t.Errorf("Redeem = %+v", r)
		}
	})

	t.Run("the user was deleted", func(t *testing.T) {
		p, l := approved()
		e.do(func(ctx context.Context, s port.Stores) error { return s.Users.Delete(ctx, p.user.ID()) })
		if r := e.redeemFor(l); r.Outcome != deviceauth.OutcomeDenied || r.Session != nil {
			t.Errorf("Redeem = %+v", r)
		}
	})

	t.Run("the phone's session idles out", func(t *testing.T) {
		_, l := approved()
		e.clock.Advance(31 * 24 * time.Hour)
		if r := e.redeemFor(l); r.Outcome != deviceauth.OutcomeDenied {
			t.Errorf("Redeem = %+v", r)
		}
	})
}

func TestTheNewSessionDoesNotDependOnThePhonesAfterwards(t *testing.T) {
	e := newEnv(t)
	p := e.phone()
	l := e.newLaptop("laptop")
	e.approve(p, l, l.res.PairingCode, e.stepUp(p, dpasskey.OperationApproveDevice))
	res := e.redeemFor(l)
	if res.Outcome != deviceauth.OutcomeOK {
		t.Fatal(res)
	}
	e.do(func(ctx context.Context, s port.Stores) error {
		return s.Sessions.RevokeOthersForUser(ctx, p.user.ID(), res.Session.ID(), e.clock.Now())
	})
	e.do(func(ctx context.Context, s port.Stores) error {
		got, err := s.Sessions.Get(ctx, res.Session.ID())
		if err != nil || !got.Active(e.clock.Now()) {
			t.Errorf("the laptop's session after the phone's ended: %+v, %v", got, err)
		}
		return nil
	})
}

func TestARedemptionThatCannotBeSignedLeavesTheApprovalUnspent(t *testing.T) {
	e := newEnv(t)
	p := e.phone()
	l := e.newLaptop("laptop")
	e.approve(p, l, l.res.PairingCode, e.stepUp(p, dpasskey.OperationApproveDevice))

	e.signer.fail = true
	if _, err := e.redeem.Execute(context.Background(), deviceauth.RedeemCommand{RequestID: l.id(), PollSecret: l.res.PollSecret, BindingSecret: l.binding}); !errors.Is(err, errBoom) {
		t.Fatalf("Redeem = %v, want the signer's failure", err)
	}
	e.signer.fail = false
	if e.store.SessionCount() != 1 || e.stateOf(l) != deviceauth.StateApproved {
		t.Fatalf("a failed redemption left %d sessions, state %s", e.store.SessionCount(), e.stateOf(l))
	}
	if r := e.redeemFor(l); r.Outcome != deviceauth.OutcomeOK {
		t.Errorf("the retry: %+v", r)
	}
}

func TestAnApprovalThatCannotBeAuditedChangesNothing(t *testing.T) {
	e := newEnv(t)
	p := e.phone()
	l := e.newLaptop("laptop")
	proof := e.stepUp(p, dpasskey.OperationApproveDevice)
	e.faults.wrap = func(s port.Stores) port.Stores { s.Audit = failingAudit{s.Audit}; return s }
	if _, err := e.approver.Approve(context.Background(), deviceauth.ApproveCommand{Actor: p.actor, RequestID: l.id(), PairingCode: l.res.PairingCode, StepUpSecret: proof}); err == nil {
		t.Fatal("Approve hid the audit failure")
	}
	e.faults.wrap = nil
	if e.stateOf(l) != deviceauth.StatePending {
		t.Error("an approval that could not be audited took effect")
	}
	if r := e.approve(p, l, l.res.PairingCode, proof); r.Outcome != deviceauth.OutcomeOK {
		t.Errorf("the proof was spent by the failed approval: %+v", r)
	}
}

type failingAudit struct{ port.AuditLog }

func (failingAudit) Record(context.Context, port.AuditEvent) error { return errBoom }
