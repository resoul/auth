package bootstrap

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"airlance.org/auth/internal/adapter/postgres"
	"airlance.org/auth/internal/testutil"
)

type fakeSweeper struct {
	mu    sync.Mutex
	calls []time.Time
	err   error
	more  int // sweeps that report a backlog before one that does not
}

func (f *fakeSweeper) Cleanup(_ context.Context, now time.Time, _ postgres.CleanupPolicy) (postgres.CleanupResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, now)
	res := postgres.CleanupResult{Flows: 1}
	if f.more > 0 {
		f.more--
		res.More = true
	}
	return res, f.err
}

func (f *fakeSweeper) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func waitForSweeps(t *testing.T, f *fakeSweeper, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for f.count() < n {
		if time.Now().After(deadline) {
			t.Fatalf("%d sweeps, want at least %d", f.count(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestSweepRunsAtStartAndEveryInterval(t *testing.T) {
	f := &fakeSweeper{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		sweepEvery(ctx, quiet(), f, testutil.NewFakeClock(time.Now()), postgres.DefaultCleanupPolicy(), 10*time.Millisecond)
		close(done)
	}()
	waitForSweeps(t, f, 3)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the sweep did not stop with its context")
	}
}

func TestSweepSurvivesAFailure(t *testing.T) {
	f := &fakeSweeper{err: errors.New("database is down")}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sweepEvery(ctx, quiet(), f, testutil.NewFakeClock(time.Now()), postgres.DefaultCleanupPolicy(), 10*time.Millisecond)
	waitForSweeps(t, f, 3)
}

func TestSweepContinuesSoonWhileABacklogRemains(t *testing.T) {
	// The interval is an hour: only the backlog rule can make a second sweep happen in time.
	f := &fakeSweeper{more: 2}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go sweepEvery(ctx, quiet(), f, testutil.NewFakeClock(time.Now()), postgres.DefaultCleanupPolicy(), time.Hour)
	waitForSweeps(t, f, 2)
}
