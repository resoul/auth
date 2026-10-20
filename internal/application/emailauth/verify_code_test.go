package emailauth_test

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"go.airlance.org/auth/internal/adapter/crypto"
	"go.airlance.org/auth/internal/application/emailauth"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/authflow"
)

func TestVerifyCreatesUserOnlyAfterProof(t *testing.T) {
	e := newEnv(t)
	flowID, binding := e.begin("Alice@Example.test")
	e.check(flowID, otherCode(e.code(flowID)), binding) // a failed proof

	if e.store.UserCount() != 0 {
		t.Fatal("a user exists before any successful proof")
	}

	res := e.check(flowID, e.code(flowID), binding)
	if res.Outcome != emailauth.OutcomeOK || res.User == nil || !res.UserCreated {
		t.Fatalf("result = %+v", res)
	}

	if res.User.Email().String() != "alice@example.test" || !res.User.EmailVerifiedAt().Equal(t0) {
		t.Errorf("user = %+v", res.User.Record())
	}

	stored, ok := e.store.User(res.User.Email())
	if !ok || stored.ID() != res.User.ID() {
		t.Error("the user was not stored")
	}

	flow := e.flow(flowID)
	if flow.State() != authflow.StateConsumed || len(flow.Salt()) != 0 || flow.Attempts() != 2 {
		t.Errorf("flow state=%s salt=%d attempts=%d", flow.State(), len(flow.Salt()), flow.Attempts())
	}
}

func TestVerifySecondUseOfTheSameProofIsDenied(t *testing.T) {
	e := newEnv(t)
	flowID, binding := e.begin("alice@example.test")
	code := e.code(flowID)

	first := e.check(flowID, code, binding)
	second := e.check(flowID, code, binding)

	if first.Outcome != emailauth.OutcomeOK {
		t.Fatalf("first = %+v", first)
	}

	if second.Outcome != emailauth.OutcomeDenied || second.Reason != emailauth.ReasonClosed || second.User != nil {
		t.Errorf("second = %+v", second)
	}

	if e.store.UserCount() != 1 {
		t.Errorf("users = %d", e.store.UserCount())
	}
}

func TestVerifyReusesExistingUser(t *testing.T) {
	e := newEnv(t)
	flowID, binding := e.begin("alice@example.test")
	first := e.check(flowID, e.code(flowID), binding)

	flowID, binding = e.begin("ALICE@example.test")

	second := e.check(flowID, e.code(flowID), binding)
	if second.Outcome != emailauth.OutcomeOK || second.UserCreated || second.User.ID() != first.User.ID() {
		t.Errorf("second = %+v (first user %s)", second, first.User.ID())
	}

	if e.store.UserCount() != 1 {
		t.Errorf("users = %d", e.store.UserCount())
	}
}

func TestVerifyWrongCodeSpendsAttemptAndKeepsFlowPending(t *testing.T) {
	e := newEnv(t)
	flowID, binding := e.begin("alice@example.test")

	res := e.check(flowID, otherCode(e.code(flowID)), binding)
	if res.Outcome != emailauth.OutcomeDenied || res.Reason != emailauth.ReasonWrongCode || res.User != nil {
		t.Fatalf("result = %+v", res)
	}

	flow := e.flow(flowID)
	if flow.Attempts() != 1 || flow.State() != authflow.StatePending {
		t.Errorf("attempts=%d state=%s", flow.Attempts(), flow.State())
	}

	if got := e.store.Spent(port.SpendVerify, flow.Email()); got != 1 {
		t.Errorf("verify quota spent = %d, want 1", got)
	}

	if e.check(flowID, e.code(flowID), binding).Outcome != emailauth.OutcomeOK {
		t.Error("the right code must still work after a wrong one")
	}
}

func TestVerifyMalformedCodeIsAWrongAttempt(t *testing.T) {
	for _, code := range []string{"", "1234567", "123456789", "abcdefgh", "1234 5678"} {
		e := newEnv(t)
		flowID, binding := e.begin("alice@example.test")

		res := e.check(flowID, code, binding)
		if res.Outcome != emailauth.OutcomeDenied || res.Reason != emailauth.ReasonWrongCode {
			t.Errorf("code %q: result = %+v", code, res)
		}

		if got := e.flow(flowID).Attempts(); got != 1 {
			t.Errorf("code %q: attempts = %d, a malformed code still spends one", code, got)
		}
	}
}

func TestVerifyLocksFlowAfterAllAttemptsFail(t *testing.T) {
	e := newEnv(t)
	flowID, binding := e.begin("alice@example.test")
	wrong := otherCode(e.code(flowID))

	for i := 1; i <= policy.MaxAttempts; i++ {
		if res := e.check(flowID, wrong, binding); res.Reason != emailauth.ReasonWrongCode {
			t.Fatalf("attempt %d: %+v", i, res)
		}
	}

	flow := e.flow(flowID)
	if flow.State() != authflow.StateLocked || len(flow.Salt()) != 0 {
		t.Fatalf("state=%s salt=%d bytes", flow.State(), len(flow.Salt()))
	}

	if res := e.check(flowID, "12345678", binding); res.Outcome != emailauth.OutcomeDenied || res.Reason != emailauth.ReasonClosed {
		t.Errorf("result after lock = %+v", res)
	}

	if e.store.UserCount() != 0 {
		t.Error("a locked flow produced a user")
	}
}

func TestVerifyFinalAttemptCanStillSucceed(t *testing.T) {
	e := newEnv(t)
	flowID, binding := e.begin("alice@example.test")

	wrong := otherCode(e.code(flowID))
	for i := 1; i < policy.MaxAttempts; i++ {
		e.check(flowID, wrong, binding)
	}

	if res := e.check(flowID, e.code(flowID), binding); res.Outcome != emailauth.OutcomeOK {
		t.Errorf("fifth attempt = %+v", res)
	}
}

func TestVerifyRefusalsAllLookTheSameToClients(t *testing.T) {
	e := newEnv(t)
	flowID, binding := e.begin("alice@example.test")
	other, otherBinding := e.begin("bob@example.test")
	code := e.code(flowID)
	absent, _ := e.ids.NewFlowID()

	expired, expiredBinding := e.begin("carol@example.test")

	locked, lockedBinding := e.begin("dave@example.test")
	for i := 0; i < policy.MaxAttempts; i++ {
		e.check(locked, otherCode(e.code(locked)), lockedBinding)
	}

	consumed, consumedBinding := e.begin("erin@example.test")
	e.check(consumed, e.code(consumed), consumedBinding)
	e.clock.Advance(policy.TTL)

	cases := map[string]emailauth.VerifyCodeCommand{
		"wrong code":       {FlowID: other, Code: otherCode(e.code(other)), BindingSecret: otherBinding},
		"unknown flow":     {FlowID: absent.String(), Code: code, BindingSecret: binding},
		"malformed flow":   {FlowID: "x", Code: code, BindingSecret: binding},
		"foreign binding":  {FlowID: flowID, Code: code, BindingSecret: otherBinding},
		"missing binding":  {FlowID: flowID, Code: code},
		"expired":          {FlowID: expired, Code: "00000000", BindingSecret: expiredBinding},
		"locked":           {FlowID: locked, Code: "00000000", BindingSecret: lockedBinding},
		"already consumed": {FlowID: consumed, Code: "00000000", BindingSecret: consumedBinding},
	}
	for name, cmd := range cases {
		res, err := e.verify.Execute(context.Background(), cmd)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		if res.Outcome != emailauth.OutcomeDenied || res.User != nil || res.UserCreated {
			t.Errorf("%s: result = %+v, want a plain denial", name, res)
		}
	}
}

func TestVerifyExpiryBoundary(t *testing.T) {
	t.Run("just before expiry succeeds", func(t *testing.T) {
		e := newEnv(t)
		flowID, binding := e.begin("alice@example.test")
		e.clock.Advance(policy.TTL - time.Nanosecond)

		if res := e.check(flowID, e.code(flowID), binding); res.Outcome != emailauth.OutcomeOK {
			t.Errorf("result = %+v", res)
		}
	})
	t.Run("at expiry is denied and recorded", func(t *testing.T) {
		e := newEnv(t)
		flowID, binding := e.begin("alice@example.test")
		code := e.code(flowID)
		e.clock.Advance(policy.TTL)

		res := e.check(flowID, code, binding)
		if res.Outcome != emailauth.OutcomeDenied || res.Reason != emailauth.ReasonExpired {
			t.Fatalf("result = %+v", res)
		}

		flow := e.flow(flowID)
		if flow.State() != authflow.StateExpired || len(flow.Salt()) != 0 || flow.Attempts() != 0 {
			t.Errorf("state=%s salt=%d attempts=%d: the expiry must be committed without spending an attempt",
				flow.State(), len(flow.Salt()), flow.Attempts())
		}

		if e.store.UserCount() != 0 {
			t.Error("an expired flow produced a user")
		}
	})
	t.Run("expiring between the two phases denies the result", func(t *testing.T) {
		e := newEnv(t)
		flowID, binding := e.begin("alice@example.test")
		e.clock.Advance(policy.TTL - time.Second)
		e.rebuildVerify(matchesHook{OTPCodes: e.otp, before: func() { e.clock.Advance(2 * time.Second) }})

		res := e.check(flowID, e.code(flowID), binding)
		if res.Outcome != emailauth.OutcomeDenied || res.Reason != emailauth.ReasonExpired {
			t.Errorf("result = %+v", res)
		}

		if e.flow(flowID).State() != authflow.StateExpired || e.store.UserCount() != 0 {
			t.Error("the flow must be expired and no user created")
		}
	})
}

func (e *env) rebuildVerify(codes port.OTPCodes) {
	e.t.Helper()

	verify, err := emailauth.NewVerifyCode(e.verifyDeps(codes))
	if err != nil {
		e.t.Fatal(err)
	}

	e.verify = verify
}

func TestVerifyWrongBindingSpendsNothing(t *testing.T) {
	e := newEnv(t)
	flowID, binding := e.begin("alice@example.test")
	_, foreign := e.begin("bob@example.test")
	code := e.code(flowID)
	before := e.flow(flowID).Record()

	for i := 0; i < policy.MaxAttempts+3; i++ {
		res := e.check(flowID, code, foreign)
		if res.Outcome != emailauth.OutcomeDenied || res.Reason != emailauth.ReasonBadBinding {
			t.Fatalf("result = %+v", res)
		}
	}

	if !reflect.DeepEqual(e.flow(flowID).Record(), before) {
		t.Error("requests with a foreign binding changed the flow")
	}

	if got := e.store.Spent(port.SpendVerify, e.flow(flowID).Email()); got != 0 {
		t.Errorf("verify quota spent = %d", got)
	}

	if e.check(flowID, code, binding).Outcome != emailauth.OutcomeOK {
		t.Error("the owner could not verify after the foreign requests")
	}
}

func TestVerifyQuotaDenialSpendsNoAttempt(t *testing.T) {
	e := newEnv(t, withLimits(-1, 1))
	flowID, binding := e.begin("alice@example.test")
	e.check(flowID, otherCode(e.code(flowID)), binding)
	before := e.flow(flowID).Record()

	res := e.check(flowID, e.code(flowID), binding)
	if res.Outcome != emailauth.OutcomeRateLimited || res.Reason != emailauth.ReasonQuota {
		t.Fatalf("result = %+v", res)
	}

	if !reflect.DeepEqual(e.flow(flowID).Record(), before) {
		t.Error("a quota denial changed the flow")
	}
}

func TestVerifyTechnicalFailureInResultKeepsSpentAttempt(t *testing.T) {
	t.Run("user store failure", func(t *testing.T) {
		e := newEnv(t)
		flowID, binding := e.begin("alice@example.test")
		code := e.code(flowID)
		e.faults.wrap = func(s port.Stores) port.Stores { s.Users = failingUsers{s.Users}; return s }

		_, err := e.verify.Execute(context.Background(), emailauth.VerifyCodeCommand{FlowID: flowID, Code: code, BindingSecret: binding})
		if !errors.Is(err, errBoom) {
			t.Fatalf("error = %v, want boom", err)
		}

		flow := e.flow(flowID)
		if flow.State() != authflow.StatePending || flow.Attempts() != 1 || e.store.UserCount() != 0 {
			t.Errorf("state=%s attempts=%d users=%d: the result must roll back, the reservation must stay",
				flow.State(), flow.Attempts(), e.store.UserCount())
		}

		// The retry makes a new reservation and succeeds.
		e.faults.wrap = nil
		if res := e.check(flowID, code, binding); res.Outcome != emailauth.OutcomeOK {
			t.Fatalf("retry = %+v", res)
		}

		if got := e.flow(flowID).Attempts(); got != 2 {
			t.Errorf("attempts after retry = %d, want 2", got)
		}
	})
	t.Run("flow save failure also rolls back the user", func(t *testing.T) {
		e := newEnv(t)
		flowID, binding := e.begin("alice@example.test")
		code := e.code(flowID)
		remaining := 1 // the reservation saves once; the result save fails
		e.faults.wrap = func(s port.Stores) port.Stores {
			s.Flows = failingSaveAfter{FlowRepository: s.Flows, remaining: &remaining}
			return s
		}

		_, err := e.verify.Execute(context.Background(), emailauth.VerifyCodeCommand{FlowID: flowID, Code: code, BindingSecret: binding})
		if !errors.Is(err, errBoom) {
			t.Fatalf("error = %v, want boom", err)
		}

		if e.flow(flowID).State() != authflow.StatePending || e.flow(flowID).Attempts() != 1 || e.store.UserCount() != 0 {
			t.Error("the failed result transaction left changes behind")
		}
	})
}

func TestVerifyKeyFailureAfterReservationKeepsSpentAttempt(t *testing.T) {
	e := newEnv(t)
	flowID, binding := e.begin("alice@example.test")

	otherRing, err := crypto.NewOTPKeyring("otp-z", map[string][]byte{"otp-z": make([]byte, 32)})
	if err != nil {
		t.Fatal(err)
	}

	otherOTP, err := crypto.NewOTP(otherRing, nil)
	if err != nil {
		t.Fatal(err)
	}

	e.rebuildVerify(otherOTP) // does not know otp-a, the key recorded in the flow

	_, err = e.verify.Execute(context.Background(), emailauth.VerifyCodeCommand{FlowID: flowID, Code: "00000000", BindingSecret: binding})
	if !errors.Is(err, crypto.ErrUnknownOTPKey) {
		t.Fatalf("error = %v, want ErrUnknownOTPKey", err)
	}

	flow := e.flow(flowID)
	if flow.Attempts() != 1 || flow.State() != authflow.StatePending {
		t.Errorf("attempts=%d state=%s: a spent attempt is not returned", flow.Attempts(), flow.State())
	}
}

func TestVerifyResendBetweenPhasesMakesTheReservationStale(t *testing.T) {
	e := newEnv(t)
	flowID, binding := e.begin("alice@example.test")
	oldCode := e.code(flowID)
	e.clock.Advance(policy.ResendPause)
	e.rebuildVerify(matchesHook{OTPCodes: e.otp, before: func() {
		if res := e.resendFlow(flowID, binding); res.Outcome != emailauth.OutcomeOK {
			t.Errorf("interleaved resend = %+v", res)
		}
	}})

	res := e.check(flowID, oldCode, binding)
	if res.Outcome != emailauth.OutcomeDenied || res.Reason != emailauth.ReasonStaleAttempt {
		t.Fatalf("result = %+v", res)
	}

	flow := e.flow(flowID)
	if flow.State() != authflow.StatePending || flow.Generation() != 2 || e.store.UserCount() != 0 {
		t.Errorf("state=%s generation=%d users=%d", flow.State(), flow.Generation(), e.store.UserCount())
	}
}

func TestConcurrentVerifiesGiveExactlyOneSuccess(t *testing.T) {
	e := newEnv(t)
	flowID, binding := e.begin("alice@example.test")
	code := e.code(flowID)

	const workers = 8

	results := make([]emailauth.VerifyCodeResult, workers)

	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()

			res, err := e.verify.Execute(context.Background(), emailauth.VerifyCodeCommand{FlowID: flowID, Code: code, BindingSecret: binding})
			if err != nil {
				t.Errorf("verify: %v", err)
			}

			results[i] = res
		}()
	}

	wg.Wait()

	ok := 0

	for _, res := range results {
		if res.Outcome == emailauth.OutcomeOK {
			ok++
		}
	}

	if ok != 1 || e.store.UserCount() != 1 {
		t.Errorf("successes = %d, users = %d; want one of each", ok, e.store.UserCount())
	}
}

func TestNewVerifyCodeRequiresDependencies(t *testing.T) {
	e := newEnv(t)

	good := e.verifyDeps(e.otp)
	for name, mutate := range map[string]func(*emailauth.VerifyCodeDeps){
		"unit of work":   func(d *emailauth.VerifyCodeDeps) { d.UnitOfWork = nil },
		"clock":          func(d *emailauth.VerifyCodeDeps) { d.Clock = nil },
		"otp":            func(d *emailauth.VerifyCodeDeps) { d.OTP = nil },
		"bindings":       func(d *emailauth.VerifyCodeDeps) { d.Bindings = nil },
		"user ids":       func(d *emailauth.VerifyCodeDeps) { d.UserIDs = nil },
		"recognized ids": func(d *emailauth.VerifyCodeDeps) { d.RecognizedIDs = nil },
		"passkey ids":    func(d *emailauth.VerifyCodeDeps) { d.PasskeyIDs = nil },
		"tickets":        func(d *emailauth.VerifyCodeDeps) { d.Tickets = nil },
		"policy":         func(d *emailauth.VerifyCodeDeps) { d.Policy = authflow.Policy{} },
	} {
		d := good
		mutate(&d)

		if _, err := emailauth.NewVerifyCode(d); err == nil {
			t.Errorf("NewVerifyCode accepted a missing %s", name)
		}
	}
}
