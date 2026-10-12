package testutil_test

import (
	"testing"
	"time"

	"airlance.org/auth/internal/domain/authflow"
	"airlance.org/auth/internal/testutil"
)

var now = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func TestFactoryBuildsDistinctValidObjects(t *testing.T) {
	f := testutil.NewFactory(t, now)

	u1, u2 := f.User(testutil.UserSpec{}), f.User(testutil.UserSpec{})
	if u1.ID() == u2.ID() || u1.Email() == u2.Email() {
		t.Errorf("users share identity: %q/%q %q/%q", u1.ID(), u2.ID(), u1.Email(), u2.Email())
	}
	f1, f2 := f.Flow(testutil.FlowSpec{}), f.Flow(testutil.FlowSpec{})
	if f1.ID() == f2.ID() || f1.Email() == f2.Email() || string(f1.Salt()) == string(f2.Salt()) {
		t.Error("flows share identity, email or salt")
	}
	if f1.State() != authflow.StatePending {
		t.Errorf("default flow state = %s", f1.State())
	}
}

func TestFactoryIsolatedBetweenInstances(t *testing.T) {
	a := testutil.NewFactory(t, now).Flow(testutil.FlowSpec{})
	b := testutil.NewFactory(t, now).Flow(testutil.FlowSpec{})
	if a.ID() != b.ID() {
		t.Errorf("fresh factories must be reproducible: %q vs %q", a.ID(), b.ID())
	}
}

func TestFactoryUsesClock(t *testing.T) {
	f := testutil.NewFactory(t, now)
	f.Clock.Advance(time.Hour)
	user := f.User(testutil.UserSpec{})
	if want := now.Add(time.Hour); !user.CreatedAt().Equal(want) {
		t.Errorf("CreatedAt = %v, want %v", user.CreatedAt(), want)
	}
}

func TestFakeClock(t *testing.T) {
	c := testutil.NewFakeClock(now)
	c.Advance(time.Minute)
	if !c.Now().Equal(now.Add(time.Minute)) {
		t.Errorf("Now() = %v", c.Now())
	}
	c.Set(now)
	if !c.Now().Equal(now) {
		t.Errorf("Now() after Set = %v", c.Now())
	}
}
