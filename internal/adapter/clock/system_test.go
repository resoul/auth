package clock_test

import (
	"testing"
	"time"

	"go.airlance.org/auth/internal/adapter/clock"
)

func TestSystemNowIsCurrentUTC(t *testing.T) {
	before := time.Now()
	got := clock.System{}.Now()
	after := time.Now()

	if got.Location() != time.UTC {
		t.Errorf("location = %v, want UTC", got.Location())
	}

	if got.Before(before.Add(-time.Second)) || got.After(after.Add(time.Second)) {
		t.Errorf("Now() = %v, outside [%v, %v]", got, before, after)
	}
}
