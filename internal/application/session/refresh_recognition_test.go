package session_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"airlance.org/auth/internal/application/port"
	appsession "airlance.org/auth/internal/application/session"
	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/testutil"
)

// recognize registers the record a successful verify of this device would have created.
func (e *env) recognize(user *identity.User, bindingSecret string) *identity.RecognizedClient {
	e.t.Helper()
	rc := e.factory.RecognizedClient(testutil.RecognizedSpec{User: user, BindingSecret: bindingSecret})
	err := e.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		_, err := st.Recognized.Register(ctx, rc)
		return err
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return rc
}

// recognizedUntil returns when the active record of the binding ends, or false if there is none.
func (e *env) recognizedUntil(user *identity.User, bindingSecret string) (time.Time, bool) {
	e.t.Helper()
	var rc *identity.RecognizedClient
	err := e.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		var err error
		rc, err = st.Recognized.FindActive(ctx, user.Email(), testutil.BindingHash(bindingSecret), e.clock.Now())
		return err
	})
	if errors.Is(err, port.ErrNotFound) {
		return time.Time{}, false
	}
	if err != nil {
		e.t.Fatal(err)
	}
	return rc.Record().ExpiresAt, true
}

func TestRefreshKeepsTheDeviceRecognizedWhileItIsInUse(t *testing.T) {
	e := newEnv(t)
	issued, user := e.login("alice@example.test")
	e.recognize(user, testutil.DefaultBindingSecret)

	secret := issued.RefreshSecret
	for step := 1; step <= 3; step++ {
		e.clock.Advance(25 * day)
		res := e.exchange(secret)
		if res.Outcome != appsession.OutcomeOK {
			t.Fatalf("refresh %d = %+v", step, res)
		}
		secret = res.NewRefreshSecret
	}

	// 95 days after the login the record of the verify has ended; the refreshes extended it.
	e.clock.Advance(20 * day)
	until, ok := e.recognizedUntil(user, testutil.DefaultBindingSecret)
	if !ok {
		t.Fatal("the device lost its recognition although it kept refreshing")
	}
	if want := t0.Add(75 * day).Add(identity.RecognitionTTL); !until.Equal(want) {
		t.Errorf("recognized until %v, want %v: 90 days after the last refresh", until, want)
	}
}

func TestRefreshDoesNotRestoreARevokedOrMissingRecord(t *testing.T) {
	e := newEnv(t)
	issued, user := e.login("alice@example.test")
	rc := e.recognize(user, testutil.DefaultBindingSecret)
	err := e.store.Do(context.Background(), func(ctx context.Context, st port.Stores) error {
		return st.Recognized.Revoke(ctx, user.ID(), rc.Record().Binding, e.clock.Now())
	})
	if err != nil {
		t.Fatal(err)
	}

	e.clock.Advance(day)
	res := e.exchange(issued.RefreshSecret)
	if res.Outcome != appsession.OutcomeOK {
		t.Fatalf("a revoked record failed the refresh: %+v", res)
	}
	if _, ok := e.recognizedUntil(user, testutil.DefaultBindingSecret); ok {
		t.Error("refresh restored a revoked record")
	}

	// A device that was never recognized refreshes without a record being invented.
	other, bob := e.login("bob@example.test")
	if res := e.exchange(other.RefreshSecret); res.Outcome != appsession.OutcomeOK {
		t.Fatalf("refresh without a record = %+v", res)
	}
	if _, ok := e.recognizedUntil(bob, testutil.DefaultBindingSecret); ok {
		t.Error("refresh created a record")
	}
}

func TestRefreshExtendsOnlyTheRecordOfTheSessionsBinding(t *testing.T) {
	e := newEnv(t)
	issued, user := e.login("alice@example.test")
	e.recognize(user, testutil.DefaultBindingSecret)
	const otherSecret = "another-device-binding-secret-000000000"
	e.recognize(user, otherSecret)
	before, _ := e.recognizedUntil(user, otherSecret)

	e.clock.Advance(10 * day)
	if res := e.exchange(issued.RefreshSecret); res.Outcome != appsession.OutcomeOK {
		t.Fatalf("refresh = %+v", res)
	}
	if after, _ := e.recognizedUntil(user, otherSecret); !after.Equal(before) {
		t.Errorf("another device's record moved from %v to %v", before, after)
	}
	if mine, _ := e.recognizedUntil(user, testutil.DefaultBindingSecret); !mine.Equal(t0.Add(10 * day).Add(identity.RecognitionTTL)) {
		t.Errorf("the record of the session was not extended: %v", mine)
	}
}

func TestADeniedOrFailedRefreshDoesNotExtendRecognition(t *testing.T) {
	e := newEnv(t)
	issued, user := e.login("alice@example.test")
	e.recognize(user, testutil.DefaultBindingSecret)
	original, _ := e.recognizedUntil(user, testutil.DefaultBindingSecret)

	// A technical failure rolls the extension back with the rest of the exchange.
	e.faults.wrap = func(s port.Stores) port.Stores { s.Tokens = failingTokenCreate{s.Tokens}; return s }
	e.clock.Advance(5 * day)
	if _, err := e.refresh.Execute(context.Background(), appsession.RefreshCommand{RefreshSecret: issued.RefreshSecret}); err == nil {
		t.Fatal("the injected failure did not surface")
	}
	e.faults.wrap = nil
	if got, _ := e.recognizedUntil(user, testutil.DefaultBindingSecret); !got.Equal(original) {
		t.Errorf("a rolled back refresh extended recognition to %v", got)
	}

	// A replay revokes the session and proves nothing about the device.
	first := e.exchange(issued.RefreshSecret)
	if first.Outcome != appsession.OutcomeOK {
		t.Fatalf("refresh = %+v", first)
	}
	extended, _ := e.recognizedUntil(user, testutil.DefaultBindingSecret)
	e.clock.Advance(5 * day)
	if res := e.exchange(issued.RefreshSecret); res.Outcome != appsession.OutcomeDenied {
		t.Fatalf("replay = %+v", res)
	}
	if got, _ := e.recognizedUntil(user, testutil.DefaultBindingSecret); !got.Equal(extended) {
		t.Errorf("a replay moved recognition from %v to %v", extended, got)
	}
}
