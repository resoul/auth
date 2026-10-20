package port

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/operator"
	"go.airlance.org/auth/internal/domain/session"
)

// AuditType names what happened. The set is closed.
type AuditType string

// Audit event types.
const (
	AuditLoginSucceeded     AuditType = "login.succeeded"
	AuditEmailVerified      AuditType = "email.verified"
	AuditPasskeyEnrolled    AuditType = "passkey.enrolled"
	AuditPasskeyRefused     AuditType = "passkey.refused"
	AuditRecoveryCodeUsed   AuditType = "recovery.code_used"
	AuditStepUpGranted      AuditType = "stepup.granted"
	AuditPasskeyDeleted     AuditType = "passkey.deleted"
	AuditRecoveryRenewed    AuditType = "recovery.codes_renewed"
	AuditAccountDeleted     AuditType = "account.deleted"
	AuditEmailChanged       AuditType = "email.changed"
	AuditInvitationUsed     AuditType = "invitation.used"
	AuditRefreshReuse       AuditType = "refresh.reuse_detected"
	AuditSessionRevoked     AuditType = "session.revoked"
	AuditAllSessionsRevoked AuditType = "sessions.revoked_all"
	// The events of operators.
	AuditOperatorLogin    AuditType = "operator.login"
	AuditOperatorEnrolled AuditType = "operator.enrolled"
	AuditOperatorChanged  AuditType = "operator.changed"
	AuditAdminAction      AuditType = "admin.action"
	// The events of the OpenID Provider. Fields carry the client ID, which has the shape of an audit value.
	AuditOIDCCodeIssued    AuditType = "oidc.code_issued"
	AuditOIDCTokensIssued  AuditType = "oidc.tokens_issued"
	AuditOIDCTokensRefresh AuditType = "oidc.tokens_refreshed"
	AuditOIDCReplay        AuditType = "oidc.replay_detected"
	AuditOIDCClientChanged AuditType = "oidc.client_changed"
	AuditOIDCLogout        AuditType = "oidc.logout"
	AuditOIDCRevoked       AuditType = "oidc.token_revoked"
	// AuditOIDCResourceChanged records a change of an API resource or of what a client may ask of it; AuditOIDCGrantEnded
	// records a grant ended by a person or by a change of rights, with the reason.
	AuditOIDCResourceChanged AuditType = "oidc.resource_changed"
	AuditOIDCGrantEnded      AuditType = "oidc.grant_ended"
	// The events of a device sign-in.
	AuditDeviceApproved AuditType = "device.approved"
	AuditDeviceDenied   AuditType = "device.denied"
)

// lastingTypes are the events someone investigates after a claim like "my account was taken over":
// they change who can get into an account, or they are the one sign of a copied key. They are rare, so
// they are kept longer than the rest.
var lastingTypes = []AuditType{
	AuditPasskeyEnrolled, AuditPasskeyDeleted, AuditRecoveryCodeUsed, AuditRecoveryRenewed,
	AuditEmailChanged, AuditAccountDeleted, AuditOperatorEnrolled, AuditOperatorChanged, AuditAdminAction, AuditDeviceApproved,
	AuditOIDCReplay, AuditOIDCClientChanged, AuditOIDCResourceChanged,
}

// LastingAuditTypes returns the event types kept for the long audit retention.
func LastingAuditTypes() []AuditType {
	return append([]AuditType(nil), lastingTypes...)
}

// CloneSuspectedReason is the reason of the refusal that marks a key whose signature counter did not
// grow; that refusal is kept for the long retention too, though the other refusals are not.
const CloneSuspectedReason = "clone_suspected"

// Lasting reports whether the event belongs to the long audit retention.
func (e AuditEvent) Lasting() bool {
	if (e.Type == AuditPasskeyRefused || e.Type == AuditOperatorLogin) && e.Fields["reason"] == CloneSuspectedReason {
		return true
	}

	for _, t := range lastingTypes {
		if e.Type == t {
			return true
		}
	}

	return false
}

// AuditResult is the outcome the event records.
type AuditResult string

// Audit results.
const (
	AuditSuccess AuditResult = "success"
	AuditDenied  AuditResult = "denied"
)

// auditFieldKeys are the only extra fields an event may carry. They hold short codes,
// never an email, IP, User-Agent, secret or free text.
var auditFieldKeys = map[string]bool{"method": true, "new_user": true, "reason": true, "quota_class": true, "scope": true, "forget_client": true, "next": true, "operation": true, "old_keys": true, "client": true, "grant": true, "resource": true}

// A value starts with a letter and has no dots, so an address, a number or a phone
// cannot pass for a code.
var auditFieldValue = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

// AuditEvent is one security-relevant fact. UserID, SessionID and OperatorID may be zero. After a
// user is deleted the references are cleared, so nothing personal remains. OperatorID names who did
// an administrative act; for those events UserID is the target.
type AuditEvent struct {
	Type       AuditType
	Result     AuditResult
	UserID     identity.UserID
	SessionID  session.ID
	OperatorID operator.ID
	At         time.Time
	Fields     map[string]string
}

// auditTypes is the closed set of event types.
var auditTypes = []AuditType{
	AuditLoginSucceeded, AuditEmailVerified, AuditPasskeyEnrolled, AuditPasskeyRefused, AuditRecoveryCodeUsed,
	AuditStepUpGranted, AuditPasskeyDeleted, AuditRecoveryRenewed, AuditEmailChanged, AuditInvitationUsed, AuditAccountDeleted,
	AuditRefreshReuse, AuditSessionRevoked, AuditAllSessionsRevoked,
	AuditOperatorLogin, AuditOperatorEnrolled, AuditOperatorChanged, AuditAdminAction, AuditDeviceApproved, AuditDeviceDenied,
	AuditOIDCCodeIssued, AuditOIDCTokensIssued, AuditOIDCTokensRefresh, AuditOIDCReplay, AuditOIDCClientChanged, AuditOIDCLogout, AuditOIDCRevoked,
	AuditOIDCResourceChanged, AuditOIDCGrantEnded,
}

// Valid reports whether t is one of the event types.
func (t AuditType) Valid() bool {
	return slices.Contains(auditTypes, t)
}

// Validate rejects an event outside the closed sets or with a field that could hold
// personal data.
func (e AuditEvent) Validate() error {
	if !e.Type.Valid() {
		return fmt.Errorf("audit: unknown event type %q", e.Type)
	}

	if e.Result != AuditSuccess && e.Result != AuditDenied {
		return fmt.Errorf("audit: unknown result %q", e.Result)
	}

	if e.At.IsZero() {
		return errors.New("audit: time is required")
	}

	for key, value := range e.Fields {
		if !auditFieldKeys[key] {
			return fmt.Errorf("audit: field %q is not allowed", key)
		}

		if !auditFieldValue.MatchString(value) {
			return fmt.Errorf("audit: field %q must be a short code of lower-case letters, digits, _ and -", key)
		}
	}

	return nil
}

// AuditLog records audit events inside the caller's transaction, so the fact is
// committed or rolled back together with what it describes.
type AuditLog interface {
	// Record stores a validated event. An invalid event is an error.
	Record(ctx context.Context, e AuditEvent) error
}
