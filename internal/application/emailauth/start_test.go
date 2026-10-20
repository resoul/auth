package emailauth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.airlance.org/auth/internal/adapter/crypto"
	"go.airlance.org/auth/internal/application/emailauth"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/authflow"
	"go.airlance.org/auth/internal/domain/identity"
)

func TestStartCreatesFlowAndOneMailJob(t *testing.T) {
	e := newEnv(t)

	res, err := e.start.Execute(context.Background(), emailauth.StartCommand{Email: "alice@example.test"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	if res.Outcome != emailauth.OutcomeOK || res.FlowID.IsZero() || res.NewBindingSecret == "" {
		t.Fatalf("result = %+v", res)
	}

	if !res.ExpiresAt.Equal(t0.Add(10*time.Minute)) || !res.ResendAfter.Equal(t0.Add(60*time.Second)) {
		t.Errorf("times = %v / %v", res.ExpiresAt, res.ResendAfter)
	}

	flow := e.flow(res.FlowID.String())

	wantBinding, err := e.bindings.HashBinding(res.NewBindingSecret)
	if err != nil {
		t.Fatal(err)
	}

	if flow.State() != authflow.StatePending || flow.Generation() != 1 || flow.Attempts() != 0 ||
		flow.Purpose() != authflow.PurposeLogin || flow.QuotaClass() != authflow.QuotaUnknown ||
		flow.BindingHash() != wantBinding {
		t.Errorf("flow = %+v", flow.Record())
	}

	jobs := e.store.OutboxJobs()
	if len(jobs) != 1 || jobs[0].FlowID != flow.ID() || jobs[0].Generation != 1 || !jobs[0].AvailableAt.Equal(t0) {
		t.Errorf("outbox = %+v", jobs)
	}

	if got := e.store.Spent(port.SpendSend, flow.Email()); got != 1 {
		t.Errorf("send quota spent = %d, want 1", got)
	}

	if e.store.UserCount() != 0 {
		t.Error("start created a user before any proof")
	}
}

func TestStartNormalizesEmail(t *testing.T) {
	e := newEnv(t)

	flowID, _ := e.begin("  Alice@Example.COM ")
	if got := e.flow(flowID).Email().String(); got != "alice@example.com" {
		t.Errorf("stored email = %q", got)
	}
}

func TestStartResponseDoesNotRevealExistingUser(t *testing.T) {
	e := newEnv(t)
	// Make alice an existing user.
	flowID, binding := e.begin("alice@example.test")
	if res := e.check(flowID, e.code(flowID), binding); res.Outcome != emailauth.OutcomeOK {
		t.Fatalf("setup verify = %+v", res)
	}

	users := e.store.UserCount()

	existing, err := e.start.Execute(context.Background(), emailauth.StartCommand{Email: "alice@example.test"})
	if err != nil {
		t.Fatal(err)
	}

	fresh, err := e.start.Execute(context.Background(), emailauth.StartCommand{Email: "bob@example.test"})
	if err != nil {
		t.Fatal(err)
	}

	if existing.Outcome != fresh.Outcome || existing.Reason != fresh.Reason ||
		!existing.ExpiresAt.Equal(fresh.ExpiresAt) || !existing.ResendAfter.Equal(fresh.ResendAfter) ||
		(existing.NewBindingSecret == "") != (fresh.NewBindingSecret == "") {
		t.Errorf("responses differ: existing %+v, new %+v", existing, fresh)
	}

	if e.store.UserCount() != users {
		t.Error("start changed the set of users")
	}
}

func TestStartReusesClientBinding(t *testing.T) {
	e := newEnv(t)
	first, secret := e.begin("alice@example.test")

	res, err := e.start.Execute(context.Background(), emailauth.StartCommand{Email: "alice@example.test", BindingSecret: secret})
	if err != nil || res.Outcome != emailauth.OutcomeOK {
		t.Fatalf("Start = %+v, %v", res, err)
	}

	if res.NewBindingSecret != "" {
		t.Error("server issued a new binding although the client sent one")
	}

	second := res.FlowID.String()
	if first == second {
		t.Fatal("flow id reused")
	}

	if e.flow(first).BindingHash() != e.flow(second).BindingHash() {
		t.Error("flows of one client have different bindings")
	}
}

func TestStartRejectsInvalidInputWithoutWriting(t *testing.T) {
	tests := []struct {
		name string
		cmd  emailauth.StartCommand
		want error
	}{
		{"empty email", emailauth.StartCommand{}, identity.ErrInvalidEmail},
		{"invalid email", emailauth.StartCommand{Email: "not-an-email"}, identity.ErrInvalidEmail},
		{"display name", emailauth.StartCommand{Email: "Alice <a@example.test>"}, identity.ErrInvalidEmail},
		{"malformed binding", emailauth.StartCommand{Email: "a@example.test", BindingSecret: "short"}, port.ErrInvalidBindingSecret},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)

			res, err := e.start.Execute(context.Background(), tt.cmd)
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}

			if res != (emailauth.StartResult{}) {
				t.Errorf("result = %+v, want zero", res)
			}

			assertNothingWritten(t, e)
		})
	}
}

func assertNothingWritten(t *testing.T, e *env) {
	t.Helper()

	if e.store.FlowCount() != 0 || len(e.store.OutboxJobs()) != 0 || e.store.UserCount() != 0 {
		t.Errorf("data written: flows=%d jobs=%d users=%d", e.store.FlowCount(), len(e.store.OutboxJobs()), e.store.UserCount())
	}
}

func TestStartBudgetDenialQueuesNothing(t *testing.T) {
	e := newEnv(t, withLimits(1, -1))
	e.begin("alice@example.test")

	res, err := e.start.Execute(context.Background(), emailauth.StartCommand{Email: "alice@example.test"})
	if err != nil {
		t.Fatal(err)
	}

	if res.Outcome != emailauth.OutcomeRateLimited || res.Reason != emailauth.ReasonQuota || !res.FlowID.IsZero() || res.NewBindingSecret != "" {
		t.Errorf("result = %+v", res)
	}

	if e.store.FlowCount() != 1 || len(e.store.OutboxJobs()) != 1 {
		t.Errorf("flows=%d jobs=%d, want the first request only", e.store.FlowCount(), len(e.store.OutboxJobs()))
	}

	if got := e.store.Spent(port.SpendSend, e.email("alice@example.test")); got != 1 {
		t.Errorf("spent = %d, want 1", got)
	}
}

func TestStartBudgetIsPerEmail(t *testing.T) {
	e := newEnv(t, withLimits(1, -1))
	e.begin("alice@example.test")
	e.begin("bob@example.test")
}

func TestStartTechnicalFailuresRollBackEverything(t *testing.T) {
	cmd := emailauth.StartCommand{Email: "alice@example.test"}

	t.Run("outbox failure rolls back flow and quota", func(t *testing.T) {
		e := newEnv(t)

		e.faults.wrap = func(s port.Stores) port.Stores { s.Outbox = failingOutbox{s.Outbox}; return s }
		if _, err := e.start.Execute(context.Background(), cmd); !errors.Is(err, errBoom) {
			t.Fatalf("error = %v, want boom", err)
		}

		assertNothingWritten(t, e)

		if got := e.store.Spent(port.SpendSend, e.email(cmd.Email)); got != 0 {
			t.Errorf("quota spent = %d after rollback", got)
		}
	})
	t.Run("flow store failure writes nothing", func(t *testing.T) {
		e := newEnv(t)

		e.faults.wrap = func(s port.Stores) port.Stores { s.Flows = failingCreate{s.Flows}; return s }
		if _, err := e.start.Execute(context.Background(), cmd); !errors.Is(err, errBoom) {
			t.Fatalf("error = %v, want boom", err)
		}

		assertNothingWritten(t, e)

		if got := e.store.Spent(port.SpendSend, e.email(cmd.Email)); got != 0 {
			t.Errorf("quota spent = %d after rollback", got)
		}
	})
}

func TestStartRandomnessFailuresWriteNothing(t *testing.T) {
	e := newEnv(t)
	cmd := emailauth.StartCommand{Email: "alice@example.test"}

	tests := map[string]emailauth.StartDeps{
		"flow id": {FlowIDs: failingFlowIDs{}, OTP: e.otp, Bindings: e.bindings},
		"otp":     {FlowIDs: e.ids, OTP: failingGenerations{}, Bindings: e.bindings},
		"binding": {FlowIDs: e.ids, OTP: e.otp, Bindings: failingBindings{}},
	}
	for name, deps := range tests {
		t.Run(name, func(t *testing.T) {
			deps.UnitOfWork, deps.Clock, deps.Policy = e.faults, e.clock, policy

			start, err := emailauth.NewStart(deps)
			if err != nil {
				t.Fatal(err)
			}

			if _, err := start.Execute(context.Background(), cmd); !errors.Is(err, errBoom) {
				t.Fatalf("error = %v, want boom", err)
			}

			assertNothingWritten(t, e)
		})
	}
}

func TestNewStartRequiresDependencies(t *testing.T) {
	e := newEnv(t)

	good := emailauth.StartDeps{UnitOfWork: e.faults, Clock: e.clock, FlowIDs: e.ids, OTP: e.otp, Bindings: crypto.Binding{}, Policy: policy}
	for name, mutate := range map[string]func(*emailauth.StartDeps){
		"unit of work": func(d *emailauth.StartDeps) { d.UnitOfWork = nil },
		"clock":        func(d *emailauth.StartDeps) { d.Clock = nil },
		"flow ids":     func(d *emailauth.StartDeps) { d.FlowIDs = nil },
		"otp":          func(d *emailauth.StartDeps) { d.OTP = nil },
		"bindings":     func(d *emailauth.StartDeps) { d.Bindings = nil },
		"policy":       func(d *emailauth.StartDeps) { d.Policy = authflow.Policy{} },
	} {
		d := good
		mutate(&d)

		if _, err := emailauth.NewStart(d); err == nil {
			t.Errorf("NewStart accepted a missing %s", name)
		}
	}

	if _, err := emailauth.NewStart(good); err != nil {
		t.Errorf("NewStart rejected valid dependencies: %v", err)
	}
}
