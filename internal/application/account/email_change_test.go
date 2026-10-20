package account_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.airlance.org/auth/internal/application/account"
	"go.airlance.org/auth/internal/application/port"
	appsession "go.airlance.org/auth/internal/application/session"
	"go.airlance.org/auth/internal/domain/authflow"
	"go.airlance.org/auth/internal/domain/identity"
	dpasskey "go.airlance.org/auth/internal/domain/passkey"
	"go.airlance.org/auth/internal/domain/quota"
	"go.airlance.org/auth/internal/testutil"
)

func TestStartQueuesACodeForTheNewAddressAndSpendsTheStepUp(t *testing.T) {
	e := newEnv(t)
	s := e.signedIn("old@example.test")
	ticket := e.stepUp(s.actor, dpasskey.OperationChangeEmail)

	got := e.startChange(s, ticket, " New@Example.test ")

	if got.Outcome != account.OutcomeOK || got.FlowID.IsZero() || !got.ExpiresAt.Equal(t0.Add(policy.TTL)) {
		t.Fatalf("start = %+v", got)
	}

	flow, ok := e.store.Flow(got.FlowID)
	if !ok {
		t.Fatal("the flow was not stored")
	}

	if flow.Purpose() != authflow.PurposeChangeEmail || flow.UserID() != s.user.ID() || flow.Email().String() != "new@example.test" ||
		flow.BindingHash() != testutil.BindingHash(s.binding) || flow.QuotaClass() != authflow.QuotaUnknown {
		t.Errorf("flow purpose=%s user=%s email=%s class=%s", flow.Purpose(), flow.UserID(), flow.Email(), flow.QuotaClass())
	}

	jobs := e.store.OutboxJobs()
	if len(jobs) != 1 || jobs[0].EffectiveKind() != port.JobCode || jobs[0].FlowID != got.FlowID || jobs[0].Generation != 1 {
		t.Errorf("jobs = %+v, want one code job for the flow", jobs)
	}

	if !e.ticketUsed(s.actor, ticket) {
		t.Error("the step-up ticket survived the start")
	}

	if again := e.startChange(s, ticket, "third@example.test"); again.Outcome != account.OutcomeStepUpRequired {
		t.Errorf("a second start with the same ticket = %+v, want step_up_required", again)
	}

	if e.store.FlowCount() != 1 {
		t.Errorf("flows = %d after a refused start", e.store.FlowCount())
	}
}

func TestStartNeedsTheStepUpOfThisSessionAndOperation(t *testing.T) {
	e := newEnv(t)
	s := e.signedIn("old@example.test")
	other := e.otherSession(s, "other-binding")

	cases := map[string]string{
		"no token":            "",
		"garbage":             "not-a-ticket",
		"another operation":   e.stepUp(s.actor, dpasskey.OperationAddPasskey),
		"another session":     e.stepUp(other, dpasskey.OperationChangeEmail),
		"a ticket nobody has": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
	}
	for name, ticket := range cases {
		t.Run(name, func(t *testing.T) {
			got := e.startChange(s, ticket, "new@example.test")
			if got.Outcome != account.OutcomeStepUpRequired || got.Reason != account.ReasonStepUp {
				t.Errorf("start = %+v, want step_up_required", got)
			}
		})
	}

	if e.store.FlowCount() != 0 || len(e.store.OutboxJobs()) != 0 {
		t.Errorf("a refused start left %d flows and %d jobs", e.store.FlowCount(), len(e.store.OutboxJobs()))
	}
}

func TestStartRefusesTheAddressTheAccountHasAndKeepsTheTicket(t *testing.T) {
	e := newEnv(t)
	s := e.signedIn("same@example.test")
	ticket := e.stepUp(s.actor, dpasskey.OperationChangeEmail)

	got := e.startChange(s, ticket, " SAME@example.test")
	if got.Outcome != account.OutcomeInvalid || got.Reason != account.ReasonSameEmail {
		t.Fatalf("start = %+v, want invalid", got)
	}

	if e.ticketUsed(s.actor, ticket) {
		t.Error("a request that changes nothing spent the step-up")
	}

	if retry := e.startChange(s, ticket, "next@example.test"); retry.Outcome != account.OutcomeOK {
		t.Errorf("the kept ticket does not work: %+v", retry)
	}
}

func TestStartCannotTellWhetherTheAddressHasAnAccount(t *testing.T) {
	e := newEnv(t)
	s := e.signedIn("old@example.test")
	e.signedIn("taken@example.test")

	free := e.startChange(s, e.stepUp(s.actor, dpasskey.OperationChangeEmail), "free@example.test")
	taken := e.startChange(s, e.stepUp(s.actor, dpasskey.OperationChangeEmail), "taken@example.test")

	if free.Outcome != account.OutcomeOK || taken.Outcome != account.OutcomeOK || free.Reason != taken.Reason {
		t.Fatalf("free = %+v, taken = %+v: the answers differ", free, taken)
	}

	if !free.ExpiresAt.Equal(taken.ExpiresAt) || len(e.store.OutboxJobs()) != 2 {
		t.Errorf("expiry %v vs %v, jobs %d", free.ExpiresAt, taken.ExpiresAt, len(e.store.OutboxJobs()))
	}
}

func TestStartRejectsAnInvalidAddressWithoutSpendingAnything(t *testing.T) {
	e := newEnv(t)
	s := e.signedIn("old@example.test")
	ticket := e.stepUp(s.actor, dpasskey.OperationChangeEmail)

	_, err := e.start.Execute(context.Background(), account.StartEmailChangeCommand{Actor: s.actor, StepUpSecret: ticket, Email: "not an address"})
	if !errors.Is(err, identity.ErrInvalidEmail) {
		t.Fatalf("error = %v, want ErrInvalidEmail", err)
	}

	if e.ticketUsed(s.actor, ticket) || e.store.FlowCount() != 0 {
		t.Error("an invalid address changed state")
	}
}

func TestStartDeniesARevokedSession(t *testing.T) {
	e := newEnv(t)
	s := e.signedIn("old@example.test")
	ticket := e.stepUp(s.actor, dpasskey.OperationChangeEmail)
	e.revoke(s.actor)

	if got := e.startChange(s, ticket, "new@example.test"); got.Outcome != account.OutcomeDenied || got.Reason != account.ReasonNoSession {
		t.Errorf("start = %+v, want denied", got)
	}

	if e.store.FlowCount() != 0 {
		t.Error("a revoked session started a flow")
	}
}

func TestStartIsBoundedByTheSendBudgetsOfTheNewAddress(t *testing.T) {
	profile, err := quota.NewProfile(map[quota.Scope][]quota.Window{quota.UnknownSendEmail: {{Limit: 1, Per: time.Hour}}})
	must(t, err)
	e := newEnv(t, withQuota(profile))
	s := e.signedIn("old@example.test")

	first := e.startChange(s, e.stepUp(s.actor, dpasskey.OperationChangeEmail), "victim@example.test")
	ticket := e.stepUp(s.actor, dpasskey.OperationChangeEmail)
	second := e.startChange(s, ticket, "victim@example.test")

	if first.Outcome != account.OutcomeOK || second.Outcome != account.OutcomeRateLimited || second.Reason != account.ReasonQuota {
		t.Fatalf("first = %+v, second = %+v", first, second)
	}

	if e.ticketUsed(s.actor, ticket) || len(e.store.OutboxJobs()) != 1 {
		t.Error("a limited start spent the ticket or queued a mail")
	}
	// Another address has its own budget.
	if other := e.startChange(s, ticket, "other@example.test"); other.Outcome != account.OutcomeOK {
		t.Errorf("another address = %+v", other)
	}
}

func TestStartLeavesNothingWhenTheQueueFails(t *testing.T) {
	e := newEnv(t)
	s := e.signedIn("old@example.test")
	ticket := e.stepUp(s.actor, dpasskey.OperationChangeEmail)
	e.faults.wrap = func(st port.Stores) port.Stores { st.Outbox = failingEnqueue{st.Outbox}; return st }

	_, err := e.start.Execute(context.Background(), account.StartEmailChangeCommand{Actor: s.actor, StepUpSecret: ticket, Email: "new@example.test"})
	if !errors.Is(err, errBoom) {
		t.Fatalf("error = %v, want boom", err)
	}

	if e.store.FlowCount() != 0 || e.ticketUsed(s.actor, ticket) {
		t.Errorf("a failed start left %d flows, ticket used = %v", e.store.FlowCount(), e.ticketUsed(s.actor, ticket))
	}
}

type failingEnqueue struct{ port.Outbox }

func (failingEnqueue) Enqueue(context.Context, port.MailJob) error { return errBoom }

func TestConfirmMovesTheAccountAndTellsTheOldAddress(t *testing.T) {
	e := newEnv(t)
	s := e.signedIn("old@example.test")
	client := e.factory.RecognizedClient(testutil.RecognizedSpec{User: s.user, BindingSecret: s.binding})
	e.do(func(ctx context.Context, st port.Stores) error {
		_, err := st.Recognized.Register(ctx, client)
		return err
	})
	flowID, code := e.begin(s, "New@Example.test")
	e.clock.Advance(time.Minute)

	got := e.confirmChange(s.actor, flowID, code)

	if got.Outcome != account.OutcomeOK || got.Email.String() != "new@example.test" {
		t.Fatalf("confirm = %+v", got)
	}

	moved, ok := e.userByEmail("new@example.test")
	if !ok || moved.ID() != s.user.ID() || !moved.EmailVerifiedAt().Equal(t0.Add(time.Minute)) || !moved.CreatedAt().Equal(t0) {
		t.Fatalf("user at the new address = %v, %v", moved, ok)
	}

	if _, ok := e.userByEmail("old@example.test"); ok {
		t.Error("the old address still has an account")
	}

	if e.store.UserCount() != 1 {
		t.Errorf("users = %d, want the same single account", e.store.UserCount())
	}

	// The old address learns of it, once, without the new address in the job.
	jobs := e.store.OutboxJobs()
	if len(jobs) != 2 || jobs[1].Kind != port.JobEmailChanged || jobs[1].Recipient.String() != "old@example.test" || jobs[1].FlowID.String() != flowID {
		t.Fatalf("jobs = %+v, want the code and then the notice for the old address", jobs)
	}

	if err := jobs[1].Validate(); err != nil {
		t.Errorf("the notice is not a valid job: %v", err)
	}

	// Recognition earned for the old address ends, and the session stays.
	e.do(func(ctx context.Context, st port.Stores) error {
		if _, err := st.Recognized.FindActive(ctx, s.user.Email(), client.Binding(), e.clock.Now()); !errors.Is(err, port.ErrNotFound) {
			t.Errorf("recognized client after the change = %v, want ErrNotFound", err)
		}

		sess, err := st.Sessions.Get(ctx, s.actor.SessionID)
		if err != nil || !sess.Active(e.clock.Now()) {
			t.Errorf("session after the change = %v, %v", sess, err)
		}

		return nil
	})

	events := e.store.AuditEvents()

	last := events[len(events)-1]
	if last.Type != port.AuditEmailChanged || last.Result != port.AuditSuccess || last.UserID != s.user.ID() || last.SessionID != s.actor.SessionID || len(last.Fields) != 0 {
		t.Errorf("audit = %+v", last)
	}

	if flow, _ := e.store.Flow(authflowID(t, flowID)); flow.State() != authflow.StateConsumed {
		t.Errorf("flow state = %s", flow.State())
	}
}

func authflowID(t *testing.T, raw string) authflow.FlowID {
	t.Helper()

	id, err := authflow.ParseFlowID(raw)
	must(t, err)

	return id
}

func TestConfirmEndsTheOtherSessionsAndKeepsTheOneThatChangedTheAddress(t *testing.T) {
	e := newEnv(t)
	s := e.signedIn("old@example.test")
	phone := e.otherSession(s, "phone-binding")
	stranger := e.signedIn("stranger@example.test")
	flowID, code := e.begin(s, "new@example.test")

	if got := e.confirmChange(s.actor, flowID, code); got.Outcome != account.OutcomeOK {
		t.Fatalf("confirm = %+v", got)
	}

	active := func(a appsession.Actor) bool {
		sess, ok := e.store.Session(a.SessionID)
		return ok && sess.Active(e.clock.Now())
	}
	if !active(s.actor) || active(phone) || !active(stranger.actor) {
		t.Errorf("sessions after the change: own=%v phone=%v stranger=%v; want true false true", active(s.actor), active(phone), active(stranger.actor))
	}

	events := e.store.AuditEvents()

	var revoked *port.AuditEvent

	for i := range events {
		if events[i].Type == port.AuditAllSessionsRevoked {
			revoked = &events[i]
		}
	}

	if revoked == nil || revoked.Fields["scope"] != "others" || revoked.Fields["reason"] != "email_changed" || revoked.UserID != s.user.ID() {
		t.Errorf("revocation audit event = %+v", revoked)
	}
}

func TestAFailedChangeEndsNoSession(t *testing.T) {
	e := newEnv(t)
	s := e.signedIn("old@example.test")
	phone := e.otherSession(s, "phone-binding")
	flowID, code := e.begin(s, "new@example.test")
	e.faults.wrap = func(st port.Stores) port.Stores { st.Outbox = failingNotice{st.Outbox}; return st }

	_, err := e.confirm.Execute(context.Background(), account.ConfirmEmailChangeCommand{Actor: s.actor, FlowID: flowID, Code: code})
	if !errors.Is(err, errBoom) {
		t.Fatalf("error = %v, want boom", err)
	}

	if sess, _ := e.store.Session(phone.SessionID); !sess.Active(e.clock.Now()) {
		t.Error("a change that rolled back ended another session")
	}
}

func TestConfirmWithTheWrongCodeSpendsAttemptsThenLocks(t *testing.T) {
	e := newEnv(t)
	s := e.signedIn("old@example.test")
	flowID, code := e.begin(s, "new@example.test")

	wrong := "00000000"
	if code == wrong {
		wrong = "11111111"
	}

	for i := 1; i <= policy.MaxAttempts; i++ {
		got := e.confirmChange(s.actor, flowID, wrong)
		if got.Outcome != account.OutcomeDenied || got.Reason != account.ReasonWrongCode {
			t.Fatalf("attempt %d = %+v", i, got)
		}
	}
	// The budget is gone: even the right code is refused now, and nothing moved.
	if got := e.confirmChange(s.actor, flowID, code); got.Outcome != account.OutcomeDenied {
		t.Errorf("the right code after the lock = %+v", got)
	}

	if _, ok := e.userByEmail("new@example.test"); ok {
		t.Error("the account moved without a proof")
	}

	if len(e.store.OutboxJobs()) != 1 {
		t.Errorf("jobs = %d, no notice is due", len(e.store.OutboxJobs()))
	}
}

func TestConfirmIsForTheAccountAndTheClientThatStarted(t *testing.T) {
	e := newEnv(t)
	s := e.signedIn("old@example.test")
	stranger := e.signedIn("stranger@example.test")
	otherDevice := e.otherSession(s, "another-binding")
	flowID, code := e.begin(s, "new@example.test")

	// Another account cannot finish it, and does not spend its attempts.
	if got := e.confirmChange(stranger.actor, flowID, code); got.Outcome != account.OutcomeDenied || got.Reason != account.ReasonUnknownFlow {
		t.Errorf("another account = %+v", got)
	}
	// The same account on a device with another binding cannot either.
	if got := e.confirmChange(otherDevice, flowID, code); got.Outcome != account.OutcomeDenied || got.Reason != account.ReasonBadBinding {
		t.Errorf("another binding = %+v", got)
	}

	flow, _ := e.store.Flow(authflowID(t, flowID))
	if flow.Attempts() != 0 || flow.State() != authflow.StatePending {
		t.Errorf("refused callers left attempts=%d state=%s", flow.Attempts(), flow.State())
	}

	if got := e.confirmChange(s.actor, flowID, code); got.Outcome != account.OutcomeOK {
		t.Errorf("the owner = %+v", got)
	}
}

func TestConfirmTakesNoOtherKindOfFlow(t *testing.T) {
	e := newEnv(t)
	s := e.signedIn("old@example.test")
	login := e.factory.Flow(testutil.FlowSpec{Email: "new@example.test", BindingSecret: s.binding, KeyID: "otp-a"})
	e.do(func(ctx context.Context, st port.Stores) error { return st.Flows.Create(ctx, login) })
	code, err := e.otp.Code(login)
	must(t, err)

	for name, id := range map[string]string{"a login flow": login.ID().String(), "garbage": "!", "an unknown flow": "AAAAAAAAAAAAAAAAAAAAAA"} {
		if got := e.confirmChange(s.actor, id, code); got.Outcome != account.OutcomeDenied || got.Reason != account.ReasonUnknownFlow {
			t.Errorf("%s = %+v", name, got)
		}
	}

	if flow, _ := e.store.Flow(login.ID()); flow.Attempts() != 0 {
		t.Error("a login flow was charged an attempt")
	}
}

func TestConfirmRefusesAReplayAnExpiredFlowAndARevokedSession(t *testing.T) {
	e := newEnv(t)
	s := e.signedIn("old@example.test")

	flowID, code := e.begin(s, "one@example.test")
	if got := e.confirmChange(s.actor, flowID, code); got.Outcome != account.OutcomeOK {
		t.Fatalf("first confirm = %+v", got)
	}

	if got := e.confirmChange(s.actor, flowID, code); got.Outcome != account.OutcomeDenied || got.Reason != account.ReasonClosed {
		t.Errorf("replay = %+v", got)
	}

	flowID, code = e.begin(s, "two@example.test")
	e.clock.Advance(policy.TTL)

	if got := e.confirmChange(s.actor, flowID, code); got.Outcome != account.OutcomeDenied || got.Reason != account.ReasonExpired {
		t.Errorf("expired = %+v", got)
	}

	flowID, code = e.begin(s, "three@example.test")
	e.revoke(s.actor)

	if got := e.confirmChange(s.actor, flowID, code); got.Outcome != account.OutcomeDenied || got.Reason != account.ReasonNoSession {
		t.Errorf("revoked session = %+v", got)
	}

	if _, ok := e.userByEmail("three@example.test"); ok {
		t.Error("a revoked session moved the account")
	}
}

func TestConfirmReportsAnAddressAnotherAccountTookMeanwhile(t *testing.T) {
	e := newEnv(t)
	s := e.signedIn("old@example.test")
	flowID, code := e.begin(s, "contested@example.test")
	e.signedIn("contested@example.test")

	got := e.confirmChange(s.actor, flowID, code)

	if got.Outcome != account.OutcomeConflict || got.Reason != account.ReasonEmailTaken {
		t.Fatalf("confirm = %+v, want a conflict", got)
	}

	if kept, ok := e.userByEmail("old@example.test"); !ok || kept.ID() != s.user.ID() {
		t.Error("the account moved despite the conflict")
	}

	if len(e.store.OutboxJobs()) != 1 {
		t.Errorf("jobs = %d: a notice went out for a change that did not happen", len(e.store.OutboxJobs()))
	}

	for _, event := range e.store.AuditEvents() {
		if event.Type == port.AuditEmailChanged {
			t.Error("an email.changed event was recorded for a change that did not happen")
		}
	}
}

func TestConfirmRollsBackWhenTheNoticeCannotBeQueued(t *testing.T) {
	e := newEnv(t)
	s := e.signedIn("old@example.test")
	flowID, code := e.begin(s, "new@example.test")
	e.faults.wrap = func(st port.Stores) port.Stores { st.Outbox = failingNotice{st.Outbox}; return st }

	_, err := e.confirm.Execute(context.Background(), account.ConfirmEmailChangeCommand{Actor: s.actor, FlowID: flowID, Code: code})
	if !errors.Is(err, errBoom) {
		t.Fatalf("error = %v, want boom", err)
	}

	if _, ok := e.userByEmail("old@example.test"); !ok {
		t.Error("the account moved although the notice failed")
	}

	if flow, _ := e.store.Flow(authflowID(t, flowID)); flow.State() != authflow.StatePending {
		t.Errorf("flow state = %s, want pending: the code was not spent", flow.State())
	}

	e.faults.wrap = nil
	if got := e.confirmChange(s.actor, flowID, code); got.Outcome != account.OutcomeOK {
		t.Errorf("the retry = %+v", got)
	}
}

func TestConfirmIsBoundedByTheVerifyBudgets(t *testing.T) {
	profile, err := quota.NewProfile(map[quota.Scope][]quota.Window{quota.UnknownVerifyEmail: {{Limit: 1, Per: time.Hour}}})
	must(t, err)
	e := newEnv(t, withQuota(profile))
	s := e.signedIn("old@example.test")
	flowID, code := e.begin(s, "new@example.test")

	if got := e.confirmChange(s.actor, flowID, "00000000"); got.Reason != account.ReasonWrongCode {
		t.Fatalf("first try = %+v", got)
	}

	got := e.confirmChange(s.actor, flowID, code)
	if got.Outcome != account.OutcomeRateLimited || got.Reason != account.ReasonQuota {
		t.Fatalf("second try = %+v, want rate limited", got)
	}

	if flow, _ := e.store.Flow(authflowID(t, flowID)); flow.Attempts() != 1 {
		t.Errorf("attempts = %d: a limited request must not spend one", flow.Attempts())
	}
}

func TestNewUseCasesNeedTheirDependencies(t *testing.T) {
	if _, err := account.NewStartEmailChange(account.StartEmailChangeDeps{}); err == nil {
		t.Error("NewStartEmailChange accepted no dependencies")
	}

	if _, err := account.NewConfirmEmailChange(account.ConfirmEmailChangeDeps{}); err == nil {
		t.Error("NewConfirmEmailChange accepted no dependencies")
	}

	e := newEnv(t)
	if _, err := account.NewStartEmailChange(account.StartEmailChangeDeps{
		UnitOfWork: e.faults, Clock: e.clock, FlowIDs: e.factory.IDs, OTP: e.otp, Tickets: e.tickets,
	}); err == nil {
		t.Error("NewStartEmailChange accepted an empty policy")
	}

	if _, err := account.NewConfirmEmailChange(account.ConfirmEmailChangeDeps{UnitOfWork: e.faults, Clock: e.clock, OTP: e.otp}); err == nil {
		t.Error("NewConfirmEmailChange accepted an empty policy")
	}
}

func TestAddressesAreCaseAndSpaceInsensitive(t *testing.T) {
	e := newEnv(t)
	s := e.signedIn("old@example.test")
	flowID, code := e.begin(s, "  MiXeD@Example.TEST ")

	got := e.confirmChange(s.actor, flowID, code)
	if got.Outcome != account.OutcomeOK || got.Email.String() != "mixed@example.test" {
		t.Fatalf("confirm = %+v", got)
	}

	if _, ok := e.userByEmail("mixed@example.test"); !ok {
		t.Error("the stored address is not normalized")
	}
}

// signingOutOTP compares like the real codes do and then signs the session out, as a request on another
// connection could between the two phases of the confirmation.
type signingOutOTP struct {
	port.OTPCodes
	signOut func()
}

func (o signingOutOTP) Matches(f *authflow.Flow, submitted string) (bool, error) {
	matched, err := o.OTPCodes.Matches(f, submitted)
	o.signOut()

	return matched, err
}

func TestConfirmRechecksTheSessionWhenTheResultIsRecorded(t *testing.T) {
	e := newEnv(t)
	s := e.signedIn("old@example.test")
	flowID, code := e.begin(s, "new@example.test")
	confirm, err := account.NewConfirmEmailChange(account.ConfirmEmailChangeDeps{
		UnitOfWork: e.faults, Clock: e.clock, OTP: signingOutOTP{e.otp, func() { e.revoke(s.actor) }}, Policy: policy,
	})
	must(t, err)

	got, err := confirm.Execute(context.Background(), account.ConfirmEmailChangeCommand{Actor: s.actor, FlowID: flowID, Code: code})
	must(t, err)

	if got.Outcome != account.OutcomeDenied || got.Reason != account.ReasonNoSession {
		t.Fatalf("confirm = %+v, want denied: the session ended during the check", got)
	}

	if _, ok := e.userByEmail("old@example.test"); !ok {
		t.Error("a signed-out session moved the account")
	}

	if len(e.store.OutboxJobs()) != 1 {
		t.Errorf("jobs = %d: no notice is due", len(e.store.OutboxJobs()))
	}
}
