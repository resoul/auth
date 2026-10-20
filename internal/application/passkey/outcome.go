package passkey

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"go.airlance.org/auth/internal/application/port"
	appsession "go.airlance.org/auth/internal/application/session"
	"go.airlance.org/auth/internal/domain/authflow"
	"go.airlance.org/auth/internal/domain/identity"
	dpasskey "go.airlance.org/auth/internal/domain/passkey"
	dsession "go.airlance.org/auth/internal/domain/session"
)

// Outcome is the externally visible result class of a use case.
type Outcome string

// Outcomes.
const (
	// OutcomeOK means the operation happened.
	OutcomeOK Outcome = "ok"
	// OutcomeDenied is an expected refusal. Every refusal looks the same to clients.
	OutcomeDenied Outcome = "denied"
	// OutcomeRateLimited means a quota stopped the request.
	OutcomeRateLimited Outcome = "rate_limited"
	// OutcomeStepUpRequired means the operation needs a fresh strong proof the request did not carry.
	OutcomeStepUpRequired Outcome = "step_up_required"
	// OutcomeNotFound means the caller has no such passkey; another user's passkey looks the same.
	OutcomeNotFound Outcome = "not_found"
	// OutcomeConflict means the operation would break a rule: the last passkey, or too many of them.
	OutcomeConflict Outcome = "conflict"
)

// Reason says why a request was refused. It is for audit and tests and must not reach clients.
type Reason string

// Reasons.
const (
	ReasonBadTicket       Reason = "bad_ticket"
	ReasonBadChallenge    Reason = "bad_challenge"
	ReasonCeremonyFailed  Reason = "ceremony_failed"
	ReasonCloneSuspected  Reason = "clone_suspected"
	ReasonBadRecoveryCode Reason = "bad_recovery_code"
	ReasonAlreadyEnrolled Reason = "already_enrolled"
	ReasonTooManyKeys     Reason = "too_many_keys"
	ReasonUnknownKey      Reason = "unknown_key"
	ReasonBadBinding      Reason = "bad_binding"
	ReasonQuota           Reason = "quota"
	ReasonStepUp          Reason = "step_up_required"
	ReasonNoSession       Reason = "no_session"
	ReasonLastKey         Reason = "last_key"
	ReasonNoKey           Reason = "no_key"
	ReasonUnknownKeyID    Reason = "unknown_key_id"
	// ReasonBlocked is a sign-in of a User an operator blocked.
	ReasonBlocked Reason = "blocked"
)

// SignedIn is a new session with its tokens. The refresh secret exists only here; the store
// keeps its hash.
type SignedIn struct {
	User             *identity.User
	Session          *dsession.Session
	Access           port.AccessToken
	RefreshSecret    string
	RefreshExpiresAt time.Time
}

// SessionDeps are what issuing a session needs.
type SessionDeps struct {
	// Sessions issues the session and its first refresh token inside the transaction.
	Sessions *appsession.Issuer
	// Signer issues the access token before the transaction commits, so a signing failure
	// rolls the whole sign-in back.
	Signer port.AccessSigner
}

func (d SessionDeps) validate(name string) error {
	if d.Sessions == nil || d.Signer == nil {
		return fmt.Errorf("new %s: all dependencies are required", name)
	}

	return nil
}

// signIn creates the session, signs its access token and records the login. method is the
// short audit code of how the User proved themselves. A client the account has not used before makes the owner
// a notice with its label, address and time; ip is the client address, the zero value is unknown.
func (d SessionDeps) signIn(ctx context.Context, st port.Stores, now time.Time, user *identity.User,
	binding identity.BindingHash, amr []string, deviceName, method string, ip netip.Addr) (SignedIn, error) {
	// Callers refuse a blocked User before they change anything; this is the net under them.
	if user.Blocked() {
		return SignedIn{}, errors.New("sign in a blocked user")
	}
	// The history is read before the session exists: the new session would make every client known.
	history, err := st.Sessions.History(ctx, user.ID(), binding)
	if err != nil {
		return SignedIn{}, fmt.Errorf("read session history: %w", err)
	}

	issued, err := d.Sessions.Issue(ctx, st, now, appsession.IssueParams{
		UserID: user.ID(), Binding: binding, AMR: amr, AuthTime: now, DeviceName: deviceName,
	})
	if err != nil {
		return SignedIn{}, fmt.Errorf("issue session: %w", err)
	}

	access, err := d.Signer.SignAccess(port.AccessClaims{
		UserID: user.ID(), SessionID: issued.Session.ID(), AuthTime: now, AMR: issued.Session.AMR(),
	})
	if err != nil {
		return SignedIn{}, fmt.Errorf("sign access token: %w", err)
	}

	if history.NewClient() {
		if err := st.Outbox.Enqueue(ctx, port.MailJob{
			Kind: port.JobNewDevice, QuotaClass: authflow.QuotaRecognized, AvailableAt: now,
			UserID: user.ID(), DeviceName: deviceName, ClientIP: ip, EventAt: now,
		}); err != nil {
			return SignedIn{}, fmt.Errorf("enqueue new device notice: %w", err)
		}
	}

	if err := st.Audit.Record(ctx, port.AuditEvent{
		Type: port.AuditLoginSucceeded, Result: port.AuditSuccess, UserID: user.ID(), SessionID: issued.Session.ID(), At: now,
		Fields: map[string]string{"method": method},
	}); err != nil {
		return SignedIn{}, fmt.Errorf("record audit event: %w", err)
	}

	return SignedIn{
		User: user, Session: issued.Session, Access: access,
		RefreshSecret: issued.RefreshSecret, RefreshExpiresAt: issued.RefreshExpiresAt,
	}, nil
}

// SignIn is signIn for the use cases of other packages that open a session after a strong proof made
// elsewhere, such as the approval of a device. Method is the audit code.
func (d SessionDeps) SignIn(ctx context.Context, st port.Stores, now time.Time, user *identity.User,
	binding identity.BindingHash, amr []string, deviceName, method string, ip netip.Addr) (SignedIn, error) {
	return d.signIn(ctx, st, now, user, binding, amr, deviceName, method, ip)
}

// Validate checks the dependencies, for the packages that build a SessionDeps of their own.
func (d SessionDeps) Validate(name string) error {
	return d.validate(name)
}

// refuse records a refused strong-factor attempt. It is best effort for the user: a refusal
// without a known user is not recorded, because audit rows name no one then.
func refuse(ctx context.Context, st port.Stores, now time.Time, userID identity.UserID, reason Reason) error {
	if userID.IsZero() {
		return nil
	}

	return st.Audit.Record(ctx, port.AuditEvent{
		Type: port.AuditPasskeyRefused, Result: port.AuditDenied, UserID: userID, At: now,
		Fields: map[string]string{"reason": string(reason)},
	})
}

// ticketDenied reports whether err means the ticket cannot be used: unknown to the store,
// expired, used or bound to something else.
func ticketDenied(err error) bool {
	return errors.Is(err, port.ErrNotFound) || errors.Is(err, dpasskey.ErrTicketExpired) ||
		errors.Is(err, dpasskey.ErrTicketUsed) || errors.Is(err, dpasskey.ErrTicketMismatch)
}

// challengeDenied reports whether err means the challenge cannot be used.
func challengeDenied(err error) bool {
	return errors.Is(err, port.ErrNotFound) || errors.Is(err, dpasskey.ErrChallengeExpired) ||
		errors.Is(err, dpasskey.ErrChallengeUsed) || errors.Is(err, dpasskey.ErrChallengePurpose)
}

// Authentication method references of the access token.
var (
	amrEnroll   = []string{"otp", "passkey"}
	amrRecovery = []string{"otp", "recovery_code", "passkey"}
	amrLogin    = []string{"passkey"}
	amrSecond   = []string{"otp", "passkey"}
)
