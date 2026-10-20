package bootstrap

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// blocking returns a component that runs until stopped.
func blocking(name string, stopped *atomic.Bool) component {
	release := make(chan struct{})

	return component{
		name: name,
		run: func(context.Context) error {
			<-release
			return nil
		},
		stop: func(context.Context) error {
			stopped.Store(true)
			close(release)

			return nil
		},
	}
}

func TestLifecycleWithoutComponentsWaitsForContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())

		done := make(chan error, 1)
		go func() { done <- newLifecycle(time.Second).run(ctx) }()

		synctest.Wait()

		select {
		case err := <-done:
			t.Fatalf("run returned early: %v", err)
		default:
		}

		cancel()

		if err := <-done; err != nil {
			t.Fatalf("run: %v", err)
		}
	})
}

func TestLifecycleStopsComponentsOnCancel(t *testing.T) {
	var stoppedA, stoppedB atomic.Bool

	lc := newLifecycle(time.Second)
	lc.add(blocking("a", &stoppedA))
	lc.add(blocking("b", &stoppedB))

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if err := lc.run(ctx); err != nil {
		t.Fatalf("run: %v", err)
	}

	if !stoppedA.Load() || !stoppedB.Load() {
		t.Errorf("stopped a=%v b=%v, want both", stoppedA.Load(), stoppedB.Load())
	}
}

func TestLifecycleComponentFailureStopsOthers(t *testing.T) {
	var stopped atomic.Bool

	boom := errors.New("boom")
	lc := newLifecycle(time.Second)
	lc.add(blocking("healthy", &stopped))
	lc.add(component{
		name: "failing",
		run:  func(context.Context) error { return boom },
		stop: func(context.Context) error { return nil },
	})

	err := lc.run(t.Context())
	if !errors.Is(err, boom) {
		t.Fatalf("run error = %v, want boom", err)
	}

	if !stopped.Load() {
		t.Error("healthy component was not stopped")
	}
}

func TestLifecycleStopReceivesDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const timeout = 5 * time.Second

		var remaining time.Duration

		lc := newLifecycle(timeout)
		lc.add(component{
			name: "c",
			run:  func(ctx context.Context) error { <-ctx.Done(); return nil },
			stop: func(ctx context.Context) error {
				deadline, ok := ctx.Deadline()
				if !ok {
					return errors.New("stop context has no deadline")
				}

				remaining = time.Until(deadline)

				return nil
			},
		})

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		if err := lc.run(ctx); err != nil {
			t.Fatalf("run: %v", err)
		}

		if remaining != timeout {
			t.Errorf("stop deadline = %v, want %v", remaining, timeout)
		}
	})
}

func TestLifecycleShutdownTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		stuck := make(chan struct{})
		defer close(stuck)

		lc := newLifecycle(3 * time.Second)
		lc.add(component{
			name: "stuck",
			run:  func(context.Context) error { <-stuck; return nil },
			stop: func(context.Context) error { return nil },
		})

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		start := time.Now()

		err := lc.run(ctx)
		if !errors.Is(err, ErrShutdownTimeout) {
			t.Fatalf("run error = %v, want ErrShutdownTimeout", err)
		}

		if got := time.Since(start); got != 3*time.Second {
			t.Errorf("waited %v, want 3s", got)
		}
	})
}
