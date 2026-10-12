package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"
)

// ErrShutdownTimeout reports that components did not stop within the shutdown deadline.
var ErrShutdownTimeout = errors.New("shutdown timed out")

// component is a long-running part of the service, such as a listener or a worker.
type component struct {
	name string
	// run blocks until the component finishes. It must return after stop is called.
	run func(ctx context.Context) error
	// stop asks the component to finish within the deadline carried by ctx.
	stop func(ctx context.Context) error
}

// lifecycle starts components together and stops them together.
type lifecycle struct {
	components      []component
	shutdownTimeout time.Duration
}

func newLifecycle(shutdownTimeout time.Duration) *lifecycle {
	return &lifecycle{shutdownTimeout: shutdownTimeout}
}

func (l *lifecycle) add(c component) {
	l.components = append(l.components, c)
}

// run starts every component and blocks until ctx is cancelled or a component
// fails. It then stops all components and waits for them for at most the
// shutdown timeout. With no components it simply waits for ctx.
func (l *lifecycle) run(ctx context.Context) error {
	g, gctx := errgroup.WithContext(ctx)
	for _, c := range l.components {
		g.Go(func() error {
			if err := c.run(gctx); err != nil {
				return fmt.Errorf("run %s: %w", c.name, err)
			}
			return nil
		})
		g.Go(func() error {
			<-gctx.Done()
			stopCtx, cancel := context.WithTimeout(context.WithoutCancel(gctx), l.shutdownTimeout)
			defer cancel()
			if err := c.stop(stopCtx); err != nil {
				return fmt.Errorf("stop %s: %w", c.name, err)
			}
			return nil
		})
	}

	// Block until shutdown begins: ctx cancelled or a component failed. Wait is
	// called only afterwards because it also cancels gctx.
	<-gctx.Done()

	done := make(chan error, 1)
	go func() { done <- g.Wait() }()

	timer := time.NewTimer(l.shutdownTimeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		return ErrShutdownTimeout
	}
}
