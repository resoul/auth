package authflow_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"go.airlance.org/auth/internal/domain/authflow"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/testutil"
)

var (
	start  = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	policy = authflow.DefaultPolicy()
)

func binding() identity.BindingHash { return testutil.BindingHash(testutil.DefaultBindingSecret) }

func TestStartCreatesPendingGenerationOne(t *testing.T) {
	f := testutil.NewFactory(t, start)
	flow := f.Flow(testutil.FlowSpec{Email: " Alice@Example.com "})

	if flow.State() != authflow.StatePending || flow.Generation() != 1 || flow.Attempts() != 0 {
		t.Errorf("state=%s generation=%d attempts=%d", flow.State(), flow.Generation(), flow.Attempts())
	}

	if flow.Email().String() != "alice@example.com" || flow.Purpose() != authflow.PurposeLogin {
		t.Errorf("email=%q purpose=%q", flow.Email(), flow.Purpose())
	}

	if want := start.Add(10 * time.Minute); !flow.ExpiresAt().Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", flow.ExpiresAt(), want)
	}

	if want := start.Add(60 * time.Second); !flow.ResendAfter().Equal(want) {
		t.Errorf("ResendAfter = %v, want %v", flow.ResendAfter(), want)
	}

	if len(flow.Salt()) != authflow.SaltLength || flow.KeyID() != testutil.DefaultKeyID {
		t.Errorf("salt len=%d keyID=%q", len(flow.Salt()), flow.KeyID())
	}

	if flow.QuotaClass() != authflow.QuotaUnknown || !flow.RecognizedClientID().IsZero() {
		t.Errorf("quota=%q recognized=%q", flow.QuotaClass(), flow.RecognizedClientID())
	}
}

func TestStartKeepsRecognizedClientForRecognizedClass(t *testing.T) {
	f := testutil.NewFactory(t, start)

	clientID, err := f.IDs.NewRecognizedClientID()
	if err != nil {
		t.Fatal(err)
	}

	flow := f.Flow(testutil.FlowSpec{QuotaClass: authflow.QuotaRecognized, RecognizedClientID: clientID})

	if flow.QuotaClass() != authflow.QuotaRecognized || flow.RecognizedClientID() != clientID {
		t.Errorf("quota=%q recognized=%q, want %q", flow.QuotaClass(), flow.RecognizedClientID(), clientID)
	}
}

func TestStartRejectsInvalidInput(t *testing.T) {
	f := testutil.NewFactory(t, start)
	good := f.Flow(testutil.FlowSpec{}).Record()
	clientID, _ := f.IDs.NewRecognizedClientID()
	userID, _ := f.IDs.NewUserID()
	params := func() authflow.StartParams {
		return authflow.StartParams{
			ID: good.ID, Email: good.Email, Purpose: authflow.PurposeLogin, Binding: good.BindingHash,
			Salt: good.Salt, KeyID: "otp-a", QuotaClass: authflow.QuotaUnknown,
		}
	}

	tests := []struct {
		name   string
		mutate func(*authflow.StartParams)
	}{
		{"zero id", func(p *authflow.StartParams) { p.ID = authflow.FlowID{} }},
		{"zero email", func(p *authflow.StartParams) { p.Email = identity.Email{} }},
		{"unknown purpose", func(p *authflow.StartParams) { p.Purpose = "signup" }},
		{"zero binding", func(p *authflow.StartParams) { p.Binding = identity.BindingHash{} }},
		{"short salt", func(p *authflow.StartParams) { p.Salt = p.Salt[:8] }},
		{"no salt", func(p *authflow.StartParams) { p.Salt = nil }},
		{"no key id", func(p *authflow.StartParams) { p.KeyID = "" }},
		{"unknown quota class", func(p *authflow.StartParams) { p.QuotaClass = "vip" }},
		{"recognized without client", func(p *authflow.StartParams) { p.QuotaClass = authflow.QuotaRecognized }},
		{"unknown class with client", func(p *authflow.StartParams) { p.RecognizedClientID = clientID }},
		{"change_email without a user", func(p *authflow.StartParams) { p.Purpose = authflow.PurposeChangeEmail }},
		{"login with a user", func(p *authflow.StartParams) { p.UserID = userID }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := params()

			p.Salt = append([]byte(nil), good.Salt...)
			tt.mutate(&p)

			if _, err := authflow.Start(p, start, policy); err == nil {
				t.Error("Start accepted invalid input")
			}
		})
	}

	if _, err := authflow.Start(params(), time.Time{}, policy); err == nil {
		t.Error("Start accepted zero time")
	}

	for name, bad := range map[string]authflow.Policy{
		"zero ttl": {MaxAttempts: 5}, "zero attempts": {TTL: time.Minute}, "negative pause": {TTL: time.Minute, MaxAttempts: 1, ResendPause: -1},
	} {
		if _, err := authflow.Start(params(), start, bad); err == nil {
			t.Errorf("Start accepted policy %s", name)
		}
	}
}

func TestChangeEmailFlowKeepsItsUserThroughStorage(t *testing.T) {
	f := testutil.NewFactory(t, start)

	userID, err := f.IDs.NewUserID()
	if err != nil {
		t.Fatal(err)
	}

	flow := f.Flow(testutil.FlowSpec{Purpose: authflow.PurposeChangeEmail, UserID: userID})
	if flow.UserID() != userID || flow.Record().UserID != userID {
		t.Fatalf("user = %s, record %s, want %s", flow.UserID(), flow.Record().UserID, userID)
	}

	restored, err := authflow.Restore(flow.Record())
	if err != nil || restored.UserID() != userID {
		t.Fatalf("Restore = %v, %v", restored, err)
	}
	// A record that lost its user, or a login flow that gained one, never existed.
	lost := flow.Record()

	lost.UserID = identity.UserID{}
	if _, err := authflow.Restore(lost); err == nil {
		t.Error("Restore accepted a change_email flow without a user")
	}

	login := f.Flow(testutil.FlowSpec{}).Record()

	login.UserID = userID
	if _, err := authflow.Restore(login); err == nil {
		t.Error("Restore accepted a login flow with a user")
	}
}

func TestFlowDoesNotAliasCallerSalt(t *testing.T) {
	f := testutil.NewFactory(t, start)
	salt := f.Salt()
	flow := f.Flow(testutil.FlowSpec{Salt: salt})

	want := append([]byte(nil), salt...)
	salt[0] ^= 0xff
	got := flow.Salt()
	got[1] ^= 0xff

	if !bytes.Equal(flow.Salt(), want) {
		t.Error("flow salt changed through caller slices")
	}
}

func TestVerifySuccessConsumesFlowOnce(t *testing.T) {
	f := testutil.NewFactory(t, start)
	flow := f.Flow(testutil.FlowSpec{})

	attempt, err := flow.Reserve(start.Add(time.Minute), authflow.PurposeLogin, binding(), policy)
	if err != nil {
		t.Fatalf("Reserve: %v", err)
	}

	if attempt.FlowID() != flow.ID() || attempt.Generation() != 1 || flow.Attempts() != 1 {
		t.Errorf("attempt=%+v attempts=%d", attempt, flow.Attempts())
	}

	if err := flow.Accept(attempt, start.Add(time.Minute)); err != nil {
		t.Fatalf("Accept: %v", err)
	}

	if flow.State() != authflow.StateConsumed || len(flow.Salt()) != 0 {
		t.Errorf("state=%s salt=%d bytes", flow.State(), len(flow.Salt()))
	}

	// Reuse: the same proof cannot succeed again, nor can a new attempt be reserved.
	if err := flow.Accept(attempt, start.Add(time.Minute)); !errors.Is(err, authflow.ErrClosed) {
		t.Errorf("second Accept error = %v, want ErrClosed", err)
	}

	if _, err := flow.Reserve(start.Add(time.Minute), authflow.PurposeLogin, binding(), policy); !errors.Is(err, authflow.ErrClosed) {
		t.Errorf("Reserve after consume error = %v, want ErrClosed", err)
	}
}

func TestTwoAttemptsOneSuccess(t *testing.T) {
	flow := testutil.NewFactory(t, start).Flow(testutil.FlowSpec{})
	now := start.Add(time.Minute)

	first, err := flow.Reserve(now, authflow.PurposeLogin, binding(), policy)
	if err != nil {
		t.Fatal(err)
	}

	second, err := flow.Reserve(now, authflow.PurposeLogin, binding(), policy)
	if err != nil {
		t.Fatal(err)
	}

	if err := flow.Accept(first, now); err != nil {
		t.Fatalf("first Accept: %v", err)
	}

	if err := flow.Accept(second, now); !errors.Is(err, authflow.ErrClosed) {
		t.Errorf("second Accept error = %v, want ErrClosed", err)
	}
}

func TestWrongCodeKeepsFlowPendingUntilAttemptsRunOut(t *testing.T) {
	flow := testutil.NewFactory(t, start).Flow(testutil.FlowSpec{})
	now := start.Add(time.Minute)

	for i := 1; i <= policy.MaxAttempts; i++ {
		attempt, err := flow.Reserve(now, authflow.PurposeLogin, binding(), policy)
		if err != nil {
			t.Fatalf("Reserve %d: %v", i, err)
		}

		if err := flow.Reject(attempt, now, policy); err != nil {
			t.Fatalf("Reject %d: %v", i, err)
		}

		wantState := authflow.StatePending
		if i == policy.MaxAttempts {
			wantState = authflow.StateLocked
		}

		if flow.State() != wantState {
			t.Fatalf("after attempt %d state = %s, want %s", i, flow.State(), wantState)
		}
	}

	if len(flow.Salt()) != 0 {
		t.Error("locked flow keeps its salt")
	}

	if _, err := flow.Reserve(now, authflow.PurposeLogin, binding(), policy); !errors.Is(err, authflow.ErrClosed) {
		t.Errorf("Reserve on locked flow error = %v, want ErrClosed", err)
	}
}

func TestLastReservedAttemptCanStillSucceed(t *testing.T) {
	flow := testutil.NewFactory(t, start).Flow(testutil.FlowSpec{})
	now := start.Add(time.Minute)

	var last authflow.Attempt

	for i := 0; i < policy.MaxAttempts; i++ {
		var err error
		if last, err = flow.Reserve(now, authflow.PurposeLogin, binding(), policy); err != nil {
			t.Fatalf("Reserve %d: %v", i+1, err)
		}
	}

	if flow.State() != authflow.StatePending {
		t.Fatalf("reserving the last attempt moved the flow to %s", flow.State())
	}

	if _, err := flow.Reserve(now, authflow.PurposeLogin, binding(), policy); !errors.Is(err, authflow.ErrAttemptsExhausted) {
		t.Fatalf("extra Reserve error = %v, want ErrAttemptsExhausted", err)
	}

	if flow.State() != authflow.StatePending || flow.Attempts() != policy.MaxAttempts {
		t.Errorf("denied Reserve changed flow: state=%s attempts=%d", flow.State(), flow.Attempts())
	}

	if err := flow.Accept(last, now); err != nil {
		t.Errorf("Accept of the last attempt: %v", err)
	}
}

func TestWrongBindingOrPurposeSpendsNothing(t *testing.T) {
	flow := testutil.NewFactory(t, start).Flow(testutil.FlowSpec{})
	now := start.Add(time.Minute)

	other := testutil.BindingHash("another-client")
	for i := 0; i < policy.MaxAttempts+2; i++ {
		if _, err := flow.Reserve(now, authflow.PurposeLogin, other, policy); !errors.Is(err, authflow.ErrBindingMismatch) {
			t.Fatalf("wrong binding error = %v, want ErrBindingMismatch", err)
		}

		if _, err := flow.Reserve(now, authflow.PurposeStepUp, binding(), policy); !errors.Is(err, authflow.ErrPurposeMismatch) {
			t.Fatalf("wrong purpose error = %v, want ErrPurposeMismatch", err)
		}
	}

	if _, err := flow.Reserve(now, authflow.PurposeLogin, identity.BindingHash{}, policy); !errors.Is(err, authflow.ErrBindingMismatch) {
		t.Errorf("zero binding error = %v, want ErrBindingMismatch", err)
	}

	if flow.Attempts() != 0 || flow.State() != authflow.StatePending {
		t.Errorf("attempts=%d state=%s", flow.Attempts(), flow.State())
	}
}

func TestPurposesAreNotInterchangeable(t *testing.T) {
	f := testutil.NewFactory(t, start)
	purposes := []authflow.Purpose{authflow.PurposeLogin, authflow.PurposeStepUp, authflow.PurposeChangeEmail}

	userID, err := f.IDs.NewUserID()
	if err != nil {
		t.Fatal(err)
	}

	for _, flowPurpose := range purposes {
		for _, requested := range purposes {
			spec := testutil.FlowSpec{Purpose: flowPurpose}
			if flowPurpose == authflow.PurposeChangeEmail {
				spec.UserID = userID
			}

			flow := f.Flow(spec)

			_, err := flow.Reserve(start, requested, binding(), policy)
			if (flowPurpose == requested) != (err == nil) {
				t.Errorf("flow %s, request %s: error = %v", flowPurpose, requested, err)
			}
		}
	}
}

func TestExpiryBoundary(t *testing.T) {
	f := testutil.NewFactory(t, start)
	expires := start.Add(policy.TTL)

	flow := f.Flow(testutil.FlowSpec{})
	if _, err := flow.Reserve(expires.Add(-time.Nanosecond), authflow.PurposeLogin, binding(), policy); err != nil {
		t.Errorf("Reserve just before expiry: %v", err)
	}

	flow = f.Flow(testutil.FlowSpec{})
	if _, err := flow.Reserve(expires, authflow.PurposeLogin, binding(), policy); !errors.Is(err, authflow.ErrExpired) {
		t.Fatalf("Reserve at expiry error = %v, want ErrExpired", err)
	}

	if flow.State() != authflow.StateExpired || len(flow.Salt()) != 0 {
		t.Errorf("state=%s salt=%d bytes", flow.State(), len(flow.Salt()))
	}

	if _, err := flow.Reserve(expires, authflow.PurposeLogin, binding(), policy); !errors.Is(err, authflow.ErrClosed) {
		t.Errorf("Reserve on expired flow error = %v, want ErrClosed", err)
	}
}

func TestExpiryDoesNotDependOnPurposeOrBinding(t *testing.T) {
	flow := testutil.NewFactory(t, start).Flow(testutil.FlowSpec{})
	late := start.Add(policy.TTL + time.Second)

	if _, err := flow.Reserve(late, authflow.PurposeStepUp, testutil.BindingHash("x"), policy); !errors.Is(err, authflow.ErrExpired) {
		t.Errorf("error = %v, want ErrExpired", err)
	}
}

func TestResultAfterExpiryIsDenied(t *testing.T) {
	flow := testutil.NewFactory(t, start).Flow(testutil.FlowSpec{})

	attempt, err := flow.Reserve(start.Add(policy.TTL-time.Second), authflow.PurposeLogin, binding(), policy)
	if err != nil {
		t.Fatal(err)
	}

	if err := flow.Accept(attempt, start.Add(policy.TTL)); !errors.Is(err, authflow.ErrExpired) {
		t.Fatalf("Accept after expiry error = %v, want ErrExpired", err)
	}

	if flow.State() != authflow.StateExpired {
		t.Errorf("state = %s", flow.State())
	}
}

func TestExpireIfDue(t *testing.T) {
	flow := testutil.NewFactory(t, start).Flow(testutil.FlowSpec{})

	if flow.ExpireIfDue(start.Add(policy.TTL - time.Nanosecond)) {
		t.Error("ExpireIfDue changed a live flow")
	}

	if !flow.ExpireIfDue(start.Add(policy.TTL)) || flow.State() != authflow.StateExpired {
		t.Errorf("ExpireIfDue did not expire the flow: state=%s", flow.State())
	}

	if flow.ExpireIfDue(start.Add(time.Hour)) {
		t.Error("ExpireIfDue changed an expired flow again")
	}

	consumed := testutil.NewFactory(t, start).Flow(testutil.FlowSpec{})

	attempt, _ := consumed.Reserve(start, authflow.PurposeLogin, binding(), policy)
	if err := consumed.Accept(attempt, start); err != nil {
		t.Fatal(err)
	}

	if consumed.ExpireIfDue(start.Add(time.Hour)) || consumed.State() != authflow.StateConsumed {
		t.Error("ExpireIfDue rewrote a consumed flow")
	}
}

func TestResendStartsNewGenerationWithoutExtendingFlow(t *testing.T) {
	f := testutil.NewFactory(t, start)
	flow := f.Flow(testutil.FlowSpec{})
	now := start.Add(2 * time.Minute)

	attempt, err := flow.Reserve(now, authflow.PurposeLogin, binding(), policy)
	if err != nil {
		t.Fatal(err)
	}

	oldSalt := flow.Salt()
	expires := flow.ExpiresAt()
	newSalt := f.Salt()

	if err := flow.Resend(now, authflow.PurposeLogin, binding(), newSalt, "otp-b", policy); err != nil {
		t.Fatalf("Resend: %v", err)
	}

	if flow.Generation() != 2 || flow.KeyID() != "otp-b" || bytes.Equal(flow.Salt(), oldSalt) || !bytes.Equal(flow.Salt(), newSalt) {
		t.Errorf("generation=%d keyID=%q salt changed=%v", flow.Generation(), flow.KeyID(), !bytes.Equal(flow.Salt(), oldSalt))
	}

	if !flow.ExpiresAt().Equal(expires) {
		t.Errorf("Resend moved ExpiresAt: %v -> %v", expires, flow.ExpiresAt())
	}

	if flow.Attempts() != 1 {
		t.Errorf("Resend reset attempts to %d", flow.Attempts())
	}

	if want := now.Add(policy.ResendPause); !flow.ResendAfter().Equal(want) {
		t.Errorf("ResendAfter = %v, want %v", flow.ResendAfter(), want)
	}

	// The comparison reserved for generation 1 can no longer prove or fail anything.
	if err := flow.Accept(attempt, now); !errors.Is(err, authflow.ErrStaleAttempt) {
		t.Errorf("Accept of stale attempt error = %v, want ErrStaleAttempt", err)
	}

	if err := flow.Reject(attempt, now, policy); !errors.Is(err, authflow.ErrStaleAttempt) {
		t.Errorf("Reject of stale attempt error = %v, want ErrStaleAttempt", err)
	}

	if flow.State() != authflow.StatePending {
		t.Errorf("stale result changed state to %s", flow.State())
	}

	fresh, err := flow.Reserve(now, authflow.PurposeLogin, binding(), policy)
	if err != nil || fresh.Generation() != 2 {
		t.Fatalf("Reserve after resend = %+v, %v", fresh, err)
	}

	if err := flow.Accept(fresh, now); err != nil {
		t.Errorf("Accept of new generation: %v", err)
	}
}

func TestResendPauseBoundary(t *testing.T) {
	f := testutil.NewFactory(t, start)
	flow := f.Flow(testutil.FlowSpec{})

	err := flow.Resend(start.Add(policy.ResendPause-time.Nanosecond), authflow.PurposeLogin, binding(), f.Salt(), "otp-a", policy)
	if !errors.Is(err, authflow.ErrResendTooSoon) {
		t.Fatalf("early Resend error = %v, want ErrResendTooSoon", err)
	}

	if flow.Generation() != 1 {
		t.Errorf("denied Resend changed generation to %d", flow.Generation())
	}

	if err := flow.Resend(start.Add(policy.ResendPause), authflow.PurposeLogin, binding(), f.Salt(), "otp-a", policy); err != nil {
		t.Errorf("Resend at the pause boundary: %v", err)
	}

	if err := flow.Resend(start.Add(policy.ResendPause), authflow.PurposeLogin, binding(), f.Salt(), "otp-a", policy); !errors.Is(err, authflow.ErrResendTooSoon) {
		t.Errorf("immediate second Resend error = %v, want ErrResendTooSoon", err)
	}
}

func TestResendDenials(t *testing.T) {
	f := testutil.NewFactory(t, start)
	now := start.Add(policy.ResendPause)

	t.Run("wrong binding", func(t *testing.T) {
		flow := f.Flow(testutil.FlowSpec{})

		err := flow.Resend(now, authflow.PurposeLogin, testutil.BindingHash("x"), f.Salt(), "otp-a", policy)
		if !errors.Is(err, authflow.ErrBindingMismatch) || flow.Generation() != 1 {
			t.Errorf("error = %v, generation = %d", err, flow.Generation())
		}
	})
	t.Run("wrong purpose", func(t *testing.T) {
		flow := f.Flow(testutil.FlowSpec{})

		err := flow.Resend(now, authflow.PurposeChangeEmail, binding(), f.Salt(), "otp-a", policy)
		if !errors.Is(err, authflow.ErrPurposeMismatch) {
			t.Errorf("error = %v", err)
		}
	})
	t.Run("expired", func(t *testing.T) {
		flow := f.Flow(testutil.FlowSpec{})

		err := flow.Resend(start.Add(policy.TTL), authflow.PurposeLogin, binding(), f.Salt(), "otp-a", policy)
		if !errors.Is(err, authflow.ErrExpired) || flow.State() != authflow.StateExpired {
			t.Errorf("error = %v, state = %s", err, flow.State())
		}
	})
	t.Run("consumed", func(t *testing.T) {
		flow := f.Flow(testutil.FlowSpec{})

		attempt, _ := flow.Reserve(start, authflow.PurposeLogin, binding(), policy)
		if err := flow.Accept(attempt, start); err != nil {
			t.Fatal(err)
		}

		err := flow.Resend(now, authflow.PurposeLogin, binding(), f.Salt(), "otp-a", policy)
		if !errors.Is(err, authflow.ErrClosed) || flow.Generation() != 1 {
			t.Errorf("error = %v, generation = %d", err, flow.Generation())
		}
	})
	t.Run("locked", func(t *testing.T) {
		flow := f.Flow(testutil.FlowSpec{})
		for i := 0; i < policy.MaxAttempts; i++ {
			attempt, _ := flow.Reserve(start, authflow.PurposeLogin, binding(), policy)
			if err := flow.Reject(attempt, start, policy); err != nil {
				t.Fatal(err)
			}
		}

		err := flow.Resend(now, authflow.PurposeLogin, binding(), f.Salt(), "otp-a", policy)
		if !errors.Is(err, authflow.ErrClosed) {
			t.Errorf("error = %v, want ErrClosed", err)
		}
	})
	t.Run("missing salt or key", func(t *testing.T) {
		flow := f.Flow(testutil.FlowSpec{})
		if err := flow.Resend(now, authflow.PurposeLogin, binding(), nil, "otp-a", policy); err == nil {
			t.Error("Resend accepted nil salt")
		}

		if err := flow.Resend(now, authflow.PurposeLogin, binding(), f.Salt(), "", policy); err == nil {
			t.Error("Resend accepted empty key id")
		}

		if flow.Generation() != 1 {
			t.Errorf("rejected Resend changed generation to %d", flow.Generation())
		}
	})
}

func TestResendCannotExtendFlowIndefinitely(t *testing.T) {
	f := testutil.NewFactory(t, start)
	flow := f.Flow(testutil.FlowSpec{})
	expires := flow.ExpiresAt()

	now := start
	for flow.Generation() < 5 {
		now = now.Add(policy.ResendPause)
		if err := flow.Resend(now, authflow.PurposeLogin, binding(), f.Salt(), "otp-a", policy); err != nil {
			t.Fatalf("Resend: %v", err)
		}
	}

	if !flow.ExpiresAt().Equal(expires) {
		t.Errorf("ExpiresAt moved to %v", flow.ExpiresAt())
	}
}

func TestPolicyOverridesLimits(t *testing.T) {
	f := testutil.NewFactory(t, start)
	tight := authflow.Policy{TTL: time.Minute, MaxAttempts: 1, ResendPause: time.Second}
	flow := f.Flow(testutil.FlowSpec{Policy: &tight})

	if want := start.Add(time.Minute); !flow.ExpiresAt().Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", flow.ExpiresAt(), want)
	}

	attempt, err := flow.Reserve(start, authflow.PurposeLogin, binding(), tight)
	if err != nil {
		t.Fatal(err)
	}

	if err := flow.Reject(attempt, start, tight); err != nil || flow.State() != authflow.StateLocked {
		t.Errorf("Reject error = %v, state = %s", err, flow.State())
	}
}
