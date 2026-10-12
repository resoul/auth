package emailauth_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"airlance.org/auth/internal/application/emailauth"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/authflow"
)

func (e *env) resendFlow(flowID, binding string) emailauth.ResendResult {
	e.t.Helper()
	res, err := e.resend.Execute(context.Background(), emailauth.ResendCommand{FlowID: flowID, BindingSecret: binding})
	if err != nil {
		e.t.Fatalf("resend: %v", err)
	}
	return res
}

func TestResendQueuesNewGenerationInSameFlow(t *testing.T) {
	e := newEnv(t)
	flowID, binding := e.begin("alice@example.test")
	before := e.flow(flowID)
	e.clock.Advance(policy.ResendPause)

	res := e.resendFlow(flowID, binding)
	if res.Outcome != emailauth.OutcomeOK {
		t.Fatalf("result = %+v", res)
	}
	flow := e.flow(flowID)
	if flow.Generation() != 2 || flow.State() != authflow.StatePending {
		t.Errorf("generation=%d state=%s", flow.Generation(), flow.State())
	}
	if string(flow.Salt()) == string(before.Salt()) {
		t.Error("resend kept the old salt")
	}
	if !flow.ExpiresAt().Equal(before.ExpiresAt()) || !res.ExpiresAt.Equal(before.ExpiresAt()) {
		t.Errorf("resend moved the expiry: %v -> %v", before.ExpiresAt(), flow.ExpiresAt())
	}
	if want := t0.Add(2 * policy.ResendPause); !res.ResendAfter.Equal(want) || !flow.ResendAfter().Equal(want) {
		t.Errorf("ResendAfter = %v, want %v", res.ResendAfter, want)
	}

	jobs := e.store.OutboxJobs()
	if len(jobs) != 2 || jobs[1].Generation != 2 || jobs[1].FlowID != flow.ID() {
		t.Errorf("outbox = %+v", jobs)
	}
	if got := e.store.Spent(port.SpendSend, flow.Email()); got != 2 {
		t.Errorf("send quota spent = %d, want 2", got)
	}
}

func TestResendInvalidatesThePreviousCode(t *testing.T) {
	e := newEnv(t)
	flowID, binding := e.begin("alice@example.test")
	oldCode := e.code(flowID)
	e.clock.Advance(policy.ResendPause)
	e.resendFlow(flowID, binding)

	if oldCode == e.code(flowID) {
		t.Skip("codes of two generations collided; the space is finite")
	}
	if res := e.check(flowID, oldCode, binding); res.Outcome != emailauth.OutcomeDenied || res.Reason != emailauth.ReasonWrongCode {
		t.Errorf("old code result = %+v", res)
	}
	if res := e.check(flowID, e.code(flowID), binding); res.Outcome != emailauth.OutcomeOK {
		t.Errorf("new code result = %+v", res)
	}
}

func TestResendBeforePauseIsRateLimitedAndChangesNothing(t *testing.T) {
	e := newEnv(t)
	flowID, binding := e.begin("alice@example.test")
	before := e.flow(flowID).Record()
	e.clock.Advance(policy.ResendPause - time.Second)

	res := e.resendFlow(flowID, binding)
	if res.Outcome != emailauth.OutcomeRateLimited || res.Reason != emailauth.ReasonResendPause {
		t.Fatalf("result = %+v", res)
	}
	if !res.ResendAfter.Equal(t0.Add(policy.ResendPause)) {
		t.Errorf("ResendAfter = %v", res.ResendAfter)
	}
	if !reflect.DeepEqual(e.flow(flowID).Record(), before) || len(e.store.OutboxJobs()) != 1 {
		t.Error("a paused resend changed the flow or queued mail")
	}
	if got := e.store.Spent(port.SpendSend, e.flow(flowID).Email()); got != 1 {
		t.Errorf("send quota spent = %d, want 1", got)
	}
}

func TestResendRefusalsChangeNothing(t *testing.T) {
	e := newEnv(t)
	flowID, binding := e.begin("alice@example.test")
	_, otherBinding := e.begin("bob@example.test")
	absent, err := e.ids.NewFlowID()
	if err != nil {
		t.Fatal(err)
	}
	e.clock.Advance(policy.ResendPause)

	tests := []struct {
		name       string
		flowID     string
		binding    string
		wantReason emailauth.Reason
	}{
		{"unknown flow", absent.String(), binding, emailauth.ReasonUnknownFlow},
		{"malformed flow id", "nope", binding, emailauth.ReasonUnknownFlow},
		{"empty flow id", "", binding, emailauth.ReasonUnknownFlow},
		{"binding of another client", flowID, otherBinding, emailauth.ReasonBadBinding},
		{"malformed binding", flowID, "short", emailauth.ReasonBadBinding},
		{"empty binding", flowID, "", emailauth.ReasonBadBinding},
	}
	before := e.flow(flowID).Record()
	jobs := len(e.store.OutboxJobs())
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := e.resendFlow(tt.flowID, tt.binding)
			if res.Outcome != emailauth.OutcomeDenied || res.Reason != tt.wantReason {
				t.Errorf("result = %+v, want denied/%s", res, tt.wantReason)
			}
			if !reflect.DeepEqual(e.flow(flowID).Record(), before) || len(e.store.OutboxJobs()) != jobs {
				t.Error("a refused resend changed data")
			}
		})
	}
}

func TestResendOnExpiredFlowRecordsExpiry(t *testing.T) {
	e := newEnv(t)
	flowID, binding := e.begin("alice@example.test")
	e.clock.Advance(policy.TTL)

	res := e.resendFlow(flowID, binding)
	if res.Outcome != emailauth.OutcomeDenied || res.Reason != emailauth.ReasonExpired {
		t.Fatalf("result = %+v", res)
	}
	flow := e.flow(flowID)
	if flow.State() != authflow.StateExpired || len(flow.Salt()) != 0 {
		t.Errorf("state=%s salt=%d bytes: the denial must be committed", flow.State(), len(flow.Salt()))
	}
	if len(e.store.OutboxJobs()) != 1 {
		t.Error("expired flow queued mail")
	}
}

func TestResendOnClosedFlowIsDenied(t *testing.T) {
	e := newEnv(t)
	flowID, binding := e.begin("alice@example.test")
	e.check(flowID, e.code(flowID), binding)
	e.clock.Advance(policy.ResendPause)

	res := e.resendFlow(flowID, binding)
	if res.Outcome != emailauth.OutcomeDenied || res.Reason != emailauth.ReasonClosed {
		t.Errorf("result = %+v", res)
	}
}

func TestResendBudgetDenialKeepsGenerationAndQueue(t *testing.T) {
	e := newEnv(t, withLimits(1, -1))
	flowID, binding := e.begin("alice@example.test")
	before := e.flow(flowID).Record()
	e.clock.Advance(policy.ResendPause)

	res := e.resendFlow(flowID, binding)
	if res.Outcome != emailauth.OutcomeRateLimited || res.Reason != emailauth.ReasonQuota {
		t.Fatalf("result = %+v", res)
	}
	if !reflect.DeepEqual(e.flow(flowID).Record(), before) || len(e.store.OutboxJobs()) != 1 {
		t.Error("a budget denial changed the flow or queued mail")
	}
}

func TestResendOutboxFailureRollsBackGeneration(t *testing.T) {
	e := newEnv(t)
	flowID, binding := e.begin("alice@example.test")
	before := e.flow(flowID).Record()
	e.clock.Advance(policy.ResendPause)
	e.faults.wrap = func(s port.Stores) port.Stores { s.Outbox = failingOutbox{s.Outbox}; return s }

	_, err := e.resend.Execute(context.Background(), emailauth.ResendCommand{FlowID: flowID, BindingSecret: binding})
	if err == nil {
		t.Fatal("expected a technical error")
	}
	if !reflect.DeepEqual(e.flow(flowID).Record(), before) {
		t.Error("generation advanced although the mail was not queued")
	}
	if got := e.store.Spent(port.SpendSend, e.flow(flowID).Email()); got != 1 {
		t.Errorf("send quota spent = %d after rollback, want 1", got)
	}
}

func TestResendKeepsSpentAttempts(t *testing.T) {
	e := newEnv(t)
	flowID, binding := e.begin("alice@example.test")
	e.check(flowID, otherCode(e.code(flowID)), binding)
	e.clock.Advance(policy.ResendPause)

	e.resendFlow(flowID, binding)
	if got := e.flow(flowID).Attempts(); got != 1 {
		t.Errorf("attempts = %d, resend must not reset them", got)
	}
}

func TestResendStaysInsideOriginalLifetime(t *testing.T) {
	e := newEnv(t)
	flowID, binding := e.begin("alice@example.test")
	expires := e.flow(flowID).ExpiresAt()
	for i := 0; i < 5; i++ {
		e.clock.Advance(policy.ResendPause)
		e.resendFlow(flowID, binding)
	}
	if !e.flow(flowID).ExpiresAt().Equal(expires) {
		t.Error("repeated resend extended the flow")
	}
}

func TestNewResendRequiresDependencies(t *testing.T) {
	e := newEnv(t)
	good := emailauth.ResendDeps{UnitOfWork: e.faults, Clock: e.clock, OTP: e.otp, Bindings: e.bindings, Policy: policy}
	for name, mutate := range map[string]func(*emailauth.ResendDeps){
		"unit of work": func(d *emailauth.ResendDeps) { d.UnitOfWork = nil },
		"clock":        func(d *emailauth.ResendDeps) { d.Clock = nil },
		"otp":          func(d *emailauth.ResendDeps) { d.OTP = nil },
		"bindings":     func(d *emailauth.ResendDeps) { d.Bindings = nil },
		"policy":       func(d *emailauth.ResendDeps) { d.Policy = authflow.Policy{} },
	} {
		d := good
		mutate(&d)
		if _, err := emailauth.NewResend(d); err == nil {
			t.Errorf("NewResend accepted a missing %s", name)
		}
	}
}
