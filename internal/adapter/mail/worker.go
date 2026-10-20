package mail

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/authflow"
)

// DeliveryPolicy holds the worker's timing and retry limits. The values follow
// Retries use growing delays and a bounded number of attempts.
type DeliveryPolicy struct {
	// MaxAttempts is how many times a job is tried before it is given up.
	MaxAttempts int
	// BaseDelay is the wait after the first failure; it doubles up to MaxDelay.
	BaseDelay time.Duration
	MaxDelay  time.Duration
	// Lease is how long a claimed job belongs to its worker. A worker that dies leaves
	// the job to be claimed again once the lease ends.
	Lease time.Duration
	// SendTimeout bounds one SMTP delivery. It must be shorter than Lease, or a slow
	// send could still be running when another worker takes the job.
	SendTimeout time.Duration
	// PollInterval is the pause when the queue is empty.
	PollInterval time.Duration
}

// DefaultDeliveryPolicy returns 5 attempts with delays of 30s, 1m, 2m, 4m, a 2 minute
// lease, a 15 second send timeout and a 1 second poll.
func DefaultDeliveryPolicy() DeliveryPolicy {
	return DeliveryPolicy{
		MaxAttempts: 5, BaseDelay: 30 * time.Second, MaxDelay: 15 * time.Minute,
		Lease: 2 * time.Minute, SendTimeout: 15 * time.Second, PollInterval: time.Second,
	}
}

// Validate rejects limits that would make the worker unsafe or useless.
func (p DeliveryPolicy) Validate() error {
	switch {
	case p.MaxAttempts < 1:
		return errors.New("delivery policy: at least one attempt is required")
	case p.BaseDelay <= 0 || p.MaxDelay < p.BaseDelay:
		return errors.New("delivery policy: delays must be positive and the maximum not below the base")
	case p.SendTimeout <= 0 || p.Lease <= p.SendTimeout:
		return errors.New("delivery policy: the lease must outlast the send timeout")
	case p.PollInterval <= 0:
		return errors.New("delivery policy: a positive poll interval is required")
	}

	return nil
}

// backoff is the wait before the next attempt after the given (1-based) failed attempt.
func (p DeliveryPolicy) backoff(attempt int) time.Duration {
	delay := p.BaseDelay
	for i := 1; i < attempt && delay < p.MaxDelay; i++ {
		delay *= 2
	}

	if delay > p.MaxDelay {
		delay = p.MaxDelay
	}

	return delay
}

// Safe reason codes stored with retried and abandoned jobs.
const (
	reasonSMTPTemporary   port.MailReason = "smtp_temporary"
	reasonSMTPRejected    port.MailReason = "smtp_rejected"
	reasonFlowObsolete    port.MailReason = "flow_obsolete"
	reasonFlowMissing     port.MailReason = "flow_missing"
	reasonKeyUnavailable  port.MailReason = "otp_key_unavailable"
	reasonRetriesExceeded port.MailReason = "attempts_exhausted"
	reasonInvitationGone  port.MailReason = "invitation_gone"
	reasonNoInvitationURL port.MailReason = "no_invitation_url"
	reasonUserGone        port.MailReason = "user_gone"
)

// WorkerDeps are the dependencies of Worker.
type WorkerDeps struct {
	UnitOfWork    port.UnitOfWork
	Clock         port.Clock
	OTP           port.OTPCodes
	Sender        port.MailSender
	Metrics       port.Metrics
	Logger        *slog.Logger
	Policy        DeliveryPolicy
	InvitationURL string
}

// Worker sends the sign-in code emails queued in the outbox. It leaves the database
// transaction before talking to the SMTP server and derives the code from the stored
// flow, so no code is ever stored.
type Worker struct {
	WorkerDeps
}

// NewWorker checks the dependencies once, at assembly time.
func NewWorker(d WorkerDeps) (*Worker, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.OTP == nil || d.Sender == nil || d.Metrics == nil || d.Logger == nil {
		return nil, errors.New("new mail worker: all dependencies are required")
	}

	if err := d.Policy.Validate(); err != nil {
		return nil, fmt.Errorf("new mail worker: %w", err)
	}

	return &Worker{d}, nil
}

// Run processes jobs until ctx is cancelled. It drains the queue, then polls. A job
// already claimed when ctx is cancelled is finished first, so shutdown does not
// cause a second delivery. It returns nil on cancellation.
func (w *Worker) Run(ctx context.Context) error {
	for {
		processed, err := w.ProcessNext(ctx)
		if ctx.Err() != nil {
			return nil
		}

		if err != nil {
			w.Logger.ErrorContext(ctx, "mail worker failed to process a job", "error", err)
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

// ProcessNext claims one ready job and delivers it. It reports whether a job was
// found. An error means the job could not be recorded as finished; its lease then
// expires and the job is tried again.
func (w *Worker) ProcessNext(ctx context.Context) (bool, error) {
	claimedAt := w.Clock.Now()

	var job port.ClaimedMail

	err := w.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		var err error

		job, err = st.Outbox.Claim(ctx, claimedAt, w.Policy.Lease)

		return err
	})
	if errors.Is(err, port.ErrNotFound) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("claim mail job: %w", err)
	}

	// From here on the job is ours: cancelling the worker must not abandon it half way.
	jobCtx := context.WithoutCancel(ctx)
	queueDelay := max(claimedAt.Sub(job.AvailableAt), 0)

	outcome, sendTime, err := w.deliver(jobCtx, job)
	if err != nil {
		return true, fmt.Errorf("finish mail job: %w", err)
	}

	w.Metrics.MailProcessed(job.QuotaClass, outcome, queueDelay, sendTime)
	w.Logger.InfoContext(ctx, "mail job processed",
		"job_id", job.ID.String(), "quota_class", string(job.QuotaClass), "outcome", string(outcome), "attempts", job.Attempts)

	return true, nil
}

type preparation int

const (
	// ready: the flow still needs this mail and the code was derived.
	ready preparation = iota
	// flowMissing: the flow is gone.
	flowMissing
	// obsolete: the flow was resent, consumed, locked or expired since the job was queued.
	obsolete
	// keyUnavailable: the OTP key of the flow cannot be used.
	keyUnavailable
	// invitationGone: the invitation was revoked, used or has expired since the job was queued.
	invitationGone
	// noInvitationURL: the worker has no link to put into an invitation.
	noInvitationURL
	// userGone: the user of a new device notice was deleted or blocked since the job was queued.
	userGone
)

// prepare loads the flow in a short transaction and decides what the job is worth.
func (w *Worker) prepare(ctx context.Context, job port.ClaimedMail) (preparation, port.Mail, error) {
	if job.Kind == port.JobInvitation {
		return w.prepareInvitation(ctx, job)
	}

	if job.Kind == port.JobNewDevice {
		return w.prepareNewDevice(ctx, job)
	}

	result := ready

	var mail port.Mail

	err := w.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		flow, err := st.Flows.Get(ctx, job.FlowID)
		if errors.Is(err, port.ErrNotFound) {
			result = flowMissing
			return nil
		}

		if err != nil {
			return err
		}

		if job.Kind == port.JobEmailChanged {
			mail = port.Mail{Kind: port.MailEmailChanged, To: job.Recipient}
			return nil
		}

		if !flow.CanDeliver(job.Generation, w.Clock.Now()) {
			result = obsolete
			return nil
		}

		code, err := w.OTP.Code(flow)
		if err != nil {
			result = keyUnavailable
			return nil
		}

		kind := port.MailSignIn
		if flow.Purpose() == authflow.PurposeChangeEmail {
			kind = port.MailConfirmEmail
		}

		mail = port.Mail{Kind: kind, To: flow.Email(), Code: code, ExpiresAt: flow.ExpiresAt()}

		return nil
	})
	if err != nil {
		return 0, port.Mail{}, fmt.Errorf("load flow: %w", err)
	}

	return result, mail, nil
}

// prepareInvitation sends the invitation only while it is still an invitation: one that the operator
// revoked, that was used to register or that has expired is not announced.
func (w *Worker) prepareInvitation(ctx context.Context, job port.ClaimedMail) (preparation, port.Mail, error) {
	if w.InvitationURL == "" {
		return noInvitationURL, port.Mail{}, nil
	}

	result := ready

	var mail port.Mail

	err := w.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		inv, err := st.Invitations.FindActive(ctx, job.Recipient, w.Clock.Now())
		if errors.Is(err, port.ErrNotFound) {
			result = invitationGone
			return nil
		}

		if err != nil {
			return err
		}

		mail = port.Mail{Kind: port.MailInvitation, To: job.Recipient, Link: w.InvitationURL, ExpiresAt: inv.ExpiresAt()}

		return nil
	})
	if err != nil {
		return 0, port.Mail{}, fmt.Errorf("load invitation: %w", err)
	}

	return result, mail, nil
}

// prepareNewDevice tells the owner of the account that a new client signed in, at the address the account has when
// the mail goes out. A user who was deleted or blocked since gets nothing: the notice would only reach a closed
// account.
func (w *Worker) prepareNewDevice(ctx context.Context, job port.ClaimedMail) (preparation, port.Mail, error) {
	result := ready

	var mail port.Mail

	err := w.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		user, err := st.Users.Get(ctx, job.UserID)
		if errors.Is(err, port.ErrNotFound) {
			result = userGone
			return nil
		}

		if err != nil {
			return err
		}

		if user.Blocked() {
			result = userGone
			return nil
		}

		mail = port.Mail{Kind: port.MailNewDevice, To: user.Email(), DeviceName: job.DeviceName, ClientIP: job.ClientIP, At: job.EventAt}

		return nil
	})
	if err != nil {
		return 0, port.Mail{}, fmt.Errorf("load user: %w", err)
	}

	return result, mail, nil
}

// deliver runs the job and records its result. It returns the outcome and the send time.
func (w *Worker) deliver(ctx context.Context, job port.ClaimedMail) (port.MailOutcome, time.Duration, error) {
	state, mail, err := w.prepare(ctx, job)
	if err != nil {
		return "", 0, err
	}

	switch state {
	case flowMissing:
		return port.MailObsolete, 0, w.abandon(ctx, job, reasonFlowMissing)
	case obsolete:
		return port.MailObsolete, 0, w.abandon(ctx, job, reasonFlowObsolete)
	case invitationGone:
		return port.MailObsolete, 0, w.abandon(ctx, job, reasonInvitationGone)
	case noInvitationURL:
		return port.MailObsolete, 0, w.abandon(ctx, job, reasonNoInvitationURL)
	case userGone:
		return port.MailObsolete, 0, w.abandon(ctx, job, reasonUserGone)
	case keyUnavailable:
		// No key, no mail: fix the keyring and the job goes out on a later attempt.
		return w.failed(ctx, job, reasonKeyUnavailable, port.MailKeyUnavailable)
	case ready:
		// The mail is prepared: send it below.
	}

	sendCtx, cancel := context.WithTimeout(ctx, w.Policy.SendTimeout)
	defer cancel()

	started := w.Clock.Now()
	sendErr := w.Sender.Send(sendCtx, mail)
	sendTime := w.Clock.Now().Sub(started)

	switch {
	case sendErr == nil:
		err := w.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
			return st.Outbox.Complete(ctx, job.ID)
		})
		if errors.Is(err, port.ErrNotFound) {
			err = nil // another worker finished it after our lease expired
		}

		return port.MailSent, sendTime, err
	case errors.Is(sendErr, port.ErrMailRejected):
		return port.MailRejected, sendTime, w.abandon(ctx, job, reasonSMTPRejected)
	default:
		outcome, _, err := w.failed(ctx, job, reasonSMTPTemporary, port.MailRetried)
		return outcome, sendTime, err
	}
}

// failed retries the job after a backoff, or gives it up once the attempts are used.
func (w *Worker) failed(ctx context.Context, job port.ClaimedMail, reason port.MailReason, outcome port.MailOutcome) (port.MailOutcome, time.Duration, error) {
	if job.Attempts >= w.Policy.MaxAttempts {
		return port.MailExhausted, 0, w.abandon(ctx, job, reasonRetriesExceeded)
	}

	retryAt := w.Clock.Now().Add(w.Policy.backoff(job.Attempts))

	err := w.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		return st.Outbox.Retry(ctx, job.ID, retryAt, reason)
	})
	if errors.Is(err, port.ErrNotFound) {
		err = nil
	}

	return outcome, 0, err
}

func (w *Worker) abandon(ctx context.Context, job port.ClaimedMail, reason port.MailReason) error {
	err := w.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		return st.Outbox.Abandon(ctx, job.ID, reason)
	})
	if errors.Is(err, port.ErrNotFound) {
		return nil
	}

	return err
}
