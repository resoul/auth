package port

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"time"

	"go.airlance.org/auth/internal/domain/authflow"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/session"
)

// MailJobKind says what a queued job sends.
type MailJobKind string

// Mail job kinds. A job belongs to a flow either way, so the flow's retention covers it.
const (
	// JobCode sends the code of the flow generation to the flow's address. It is the zero
	// value's meaning too, so a MailJob built without a kind is a code job.
	JobCode MailJobKind = "code"
	// JobEmailChanged tells the old address that the account moved to another one. Recipient
	// holds that address: the flow's own address is the new one.
	JobEmailChanged MailJobKind = "email_changed"
	// JobInvitation tells an address that it is invited to register. It belongs to no flow: Recipient
	// is the address, and the worker looks the invitation up when it sends, so one that was revoked,
	// used or has expired sends nothing.
	JobInvitation MailJobKind = "invitation"
	// JobNewDevice tells a user that a device or an app they had not used before signed in. It belongs to no flow:
	// UserID names the account, and the worker reads the user's address when it sends, so a deleted or blocked
	// user gets nothing. ClientIP is kept only to be put into the mail and is gone when the job ends.
	JobNewDevice MailJobKind = "new_device"
)

// MailJob asks the mail worker to send the code of one flow generation, or a notice about
// the flow. It holds no code: the worker derives it from the stored flow.
type MailJob struct {
	Kind        MailJobKind
	FlowID      authflow.FlowID
	Generation  uint64
	QuotaClass  authflow.QuotaClass
	AvailableAt time.Time
	// Recipient is set exactly for JobEmailChanged and JobInvitation.
	Recipient identity.Email
	// UserID, DeviceName, ClientIP and EventAt belong to JobNewDevice: who signed in, the label the client gave,
	// the address it came from (the zero value is unknown) and when.
	UserID     identity.UserID
	DeviceName string
	ClientIP   netip.Addr
	EventAt    time.Time
}

// EffectiveKind returns the kind of the job: JobCode when none was set.
func (j MailJob) EffectiveKind() MailJobKind {
	if j.Kind == "" {
		return JobCode
	}

	return j.Kind
}

// Validate rejects a job that no worker could carry out.
func (j MailJob) Validate() error {
	switch j.EffectiveKind() {
	case JobCode:
		if !j.Recipient.IsZero() {
			return errors.New("mail job: a code job sends to its flow's address")
		}
	case JobEmailChanged:
		if j.Recipient.IsZero() {
			return errors.New("mail job: a notice needs a recipient")
		}
	case JobNewDevice:
		switch {
		case j.UserID.IsZero() || j.EventAt.IsZero():
			return errors.New("mail job: a new device notice needs a user and a time")
		case !j.FlowID.IsZero() || !j.Recipient.IsZero():
			return errors.New("mail job: a new device notice belongs to no flow and names no address")
		case !session.ValidDeviceName(j.DeviceName):
			return errors.New("mail job: invalid device name")
		}

		return nil
	case JobInvitation:
		if j.Recipient.IsZero() {
			return errors.New("mail job: an invitation needs a recipient")
		}

		if !j.FlowID.IsZero() {
			return errors.New("mail job: an invitation belongs to no flow")
		}

		return nil
	default:
		return fmt.Errorf("mail job: unknown kind %q", j.Kind)
	}

	if j.FlowID.IsZero() || j.Generation == 0 {
		return errors.New("mail job: a flow and its generation are required")
	}

	return nil
}

// MailJobID identifies a queued job. It is a canonical lower-case UUID.
type MailJobID struct{ value string }

var mailJobIDFormat = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ParseMailJobID validates the canonical UUID text form.
func ParseMailJobID(s string) (MailJobID, error) {
	if !mailJobIDFormat.MatchString(s) {
		return MailJobID{}, errors.New("invalid mail job id")
	}

	return MailJobID{value: s}, nil
}

// String returns the canonical text form.
func (id MailJobID) String() string { return id.value }

// IsZero reports whether id is the invalid zero value.
func (id MailJobID) IsZero() bool { return id.value == "" }

// ClaimedMail is a job leased to one worker. Attempts counts this claim, so the
// first delivery attempt has Attempts 1 and a crashed worker's job comes back with
// a higher number.
type ClaimedMail struct {
	Kind        MailJobKind
	Recipient   identity.Email
	ID          MailJobID
	FlowID      authflow.FlowID
	Generation  uint64
	QuotaClass  authflow.QuotaClass
	Attempts    int
	AvailableAt time.Time
	UserID      identity.UserID
	DeviceName  string
	ClientIP    netip.Addr
	EventAt     time.Time
}

// MailReason is a safe code stored with a job that was retried or abandoned: lower
// case letters, digits and underscores, starting with a letter, at most 64 characters.
// It never carries an SMTP message, an address or a code.
type MailReason string

var mailReasonFormat = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// Valid reports whether r is a safe code.
func (r MailReason) Valid() bool { return mailReasonFormat.MatchString(string(r)) }

// QueueStats describes the jobs waiting to be sent, per quota class.
type QueueStats struct {
	Queued map[authflow.QuotaClass]int
	// OldestWait is how long the oldest due job has been waiting; zero when none is due.
	OldestWait map[authflow.QuotaClass]time.Duration
}

// Outbox is the durable mail queue. Every method is part of the caller's transaction.
type Outbox interface {
	// Enqueue adds the job of a flow generation. A second job for the same flow
	// generation is an error.
	Enqueue(ctx context.Context, job MailJob) error
	// Claim leases the next job that is queued, due at now and not leased, and counts
	// the attempt. Jobs of recognized clients are taken before the others, so they never
	// wait behind a queue of unknown senders. Concurrent callers never get the same job.
	// The lease ends at now plus lease; an expired lease makes the job claimable again.
	// It returns ErrNotFound when nothing is ready.
	Claim(ctx context.Context, now time.Time, lease time.Duration) (ClaimedMail, error)
	// Complete marks the job sent and releases the lease. It returns ErrNotFound if the
	// job is no longer queued.
	Complete(ctx context.Context, id MailJobID) error
	// Retry puts the job back in the queue, due at availableAt, with the reason of the
	// failure. It returns ErrNotFound if the job is no longer queued.
	Retry(ctx context.Context, id MailJobID, availableAt time.Time, reason MailReason) error
	// Abandon gives the job up for good, with the reason. It returns ErrNotFound if the
	// job is no longer queued.
	Abandon(ctx context.Context, id MailJobID, reason MailReason) error
	// Stats reports the queue for metrics.
	Stats(ctx context.Context, now time.Time) (QueueStats, error)
}
