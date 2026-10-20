package oidclogout

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.airlance.org/auth/internal/application/port"
)

// Policy holds the timing of delivery.
type Policy struct {
	// PollInterval is how long the worker rests when nothing is due.
	PollInterval time.Duration
	// Lease is how long a claimed notice is the worker's; a worker that dies lets it go.
	Lease time.Duration
	// Backoff is the wait before each next attempt; the last entry repeats until the notice expires.
	Backoff []time.Duration
}

// DefaultPolicy tries at once, then after a minute, five minutes, half an hour, two hours and six, until the notice
// expires after a day.
func DefaultPolicy() Policy {
	return Policy{
		PollInterval: 2 * time.Second, Lease: time.Minute,
		Backoff: []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute, 2 * time.Hour, 6 * time.Hour},
	}
}

// Validate refuses a policy that cannot work.
func (p Policy) Validate() error {
	if p.PollInterval <= 0 || p.Lease <= 0 || len(p.Backoff) == 0 {
		return errors.New("oidc logout policy: a poll interval, a lease and a backoff are required")
	}

	for _, d := range p.Backoff {
		if d <= 0 {
			return errors.New("oidc logout policy: every backoff step must be positive")
		}
	}

	return nil
}

// Safe reason codes stored with retried and abandoned notices.
const (
	reasonDelivered   = "delivered"
	reasonNoEndpoint  = "no_endpoint"
	reasonExpired     = "expired"
	reasonBlocked     = "address_blocked"
	reasonUnreachable = "unreachable"
	reasonRejected    = "rejected"
	reasonRedirect    = "unexpected_redirect"
	reasonExhausted   = "attempts_exhausted"
)

// Deps are the dependencies of Worker.
type Deps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
	Signer     port.OIDCSigner
	// HTTP is the client that makes the call; use NewHTTPClient.
	HTTP   *http.Client
	Logger *slog.Logger
	Policy Policy
}

// Worker sends the logout notices queued when sign-ins ended. It leaves the database transaction before it talks to
// anyone, and signs a fresh token for every attempt: the jti stays the notice's own, so a client that gets one twice can see
// it is the same.
type Worker struct{ Deps }

// NewWorker checks the dependencies once, at assembly time.
func NewWorker(d Deps) (*Worker, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.Signer == nil || d.HTTP == nil || d.Logger == nil {
		return nil, errors.New("new oidc logout worker: all dependencies are required")
	}

	if err := d.Policy.Validate(); err != nil {
		return nil, fmt.Errorf("new oidc logout worker: %w", err)
	}

	return &Worker{d}, nil
}

// Run delivers notices until ctx is cancelled: it drains what is due, then polls. A notice claimed when ctx is cancelled is
// finished first. It returns nil on cancellation.
func (w *Worker) Run(ctx context.Context) error {
	for {
		processed, err := w.ProcessNext(ctx)
		if ctx.Err() != nil {
			return nil
		}

		if err != nil {
			w.Logger.ErrorContext(ctx, "logout notice worker failed to process a notice", "error", err)
		}

		if processed && err == nil {
			continue
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(w.Policy.PollInterval):
		}
	}
}

// ProcessNext claims one due notice and delivers it. It reports whether one was found. An error means the outcome could not
// be recorded; the lease then runs out and the notice is tried again.
func (w *Worker) ProcessNext(ctx context.Context) (bool, error) {
	now := w.Clock.Now()

	var notice *port.ClaimedLogout

	err := w.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		var err error

		notice, err = st.OIDCLogout.Claim(ctx, now, now.Add(w.Policy.Lease))
		if errors.Is(err, port.ErrNotFound) {
			notice = nil
			return nil
		}

		return err
	})
	if err != nil {
		return false, fmt.Errorf("claim logout notice: %w", err)
	}

	if notice == nil {
		return false, nil
	}

	reason, retry := w.deliver(ctx, notice, now)

	err = w.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		switch {
		case reason == reasonDelivered:
			return st.OIDCLogout.Complete(ctx, notice.ID)
		case retry && now.Before(notice.ExpiresAt):
			next := now.Add(w.backoff(notice.Attempts))
			if next.After(notice.ExpiresAt) {
				return st.OIDCLogout.Abandon(ctx, notice.ID, reasonExhausted)
			}

			return st.OIDCLogout.Retry(ctx, notice.ID, next, reason)
		case retry:
			return st.OIDCLogout.Abandon(ctx, notice.ID, reasonExhausted)
		default:
			return st.OIDCLogout.Abandon(ctx, notice.ID, reason)
		}
	})
	if err != nil {
		return true, fmt.Errorf("record logout notice outcome: %w", err)
	}

	w.Logger.InfoContext(ctx, "logout notice processed", "client", notice.ClientID, "outcome", reason, "attempt", notice.Attempts)

	return true, nil
}

func (w *Worker) backoff(attempts int) time.Duration {
	i := attempts - 1
	if i < 0 {
		i = 0
	}

	if i >= len(w.Policy.Backoff) {
		i = len(w.Policy.Backoff) - 1
	}

	return w.Policy.Backoff[i]
}

// deliver makes one attempt and says how it ended: a reason code, and whether another attempt may help.
func (w *Worker) deliver(ctx context.Context, n *port.ClaimedLogout, now time.Time) (reason string, retry bool) {
	if n.BackchannelURI == "" {
		return reasonNoEndpoint, false
	}

	if !now.Before(n.ExpiresAt) {
		return reasonExpired, false
	}

	token, err := w.Signer.SignLogoutToken(port.LogoutClaims{Subject: n.UserID, ClientID: n.ClientID, SessionID: n.SessionID, JTI: n.ID})
	if err != nil {
		w.Logger.ErrorContext(ctx, "sign logout token", "error", err)
		return reasonUnreachable, true
	}

	form := url.Values{"logout_token": {token.Value}}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.BackchannelURI, strings.NewReader(form.Encode()))
	if err != nil {
		return reasonNoEndpoint, false
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cache-Control", "no-store")

	resp, err := w.HTTP.Do(req)
	if err != nil {
		if errors.Is(err, errBlocked) {
			return reasonBlocked, false
		}

		return reasonUnreachable, true
	}

	defer func() { _ = resp.Body.Close() }()

	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10)) // nothing in the answer is used
	switch {
	case resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent:
		return reasonDelivered, false
	case resp.StatusCode == http.StatusBadRequest:
		// The client understood the notice and refused it; sending it again will not change that.
		return reasonRejected, false
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return reasonRedirect, true
	default:
		return fmt.Sprintf("status_%d", resp.StatusCode), true
	}
}
