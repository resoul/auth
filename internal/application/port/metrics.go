package port

import (
	"time"

	"go.airlance.org/auth/internal/domain/authflow"
)

// MailOutcome is what happened to one delivery attempt. The set is closed so that it
// is safe as a metric label.
type MailOutcome string

// Mail outcomes.
const (
	MailSent           MailOutcome = "sent"
	MailRetried        MailOutcome = "retried"
	MailRejected       MailOutcome = "rejected"
	MailObsolete       MailOutcome = "obsolete"
	MailExhausted      MailOutcome = "exhausted"
	MailKeyUnavailable MailOutcome = "key_unavailable"
)

// Metrics records the counters operators watch. Labels come from closed sets; no
// email, IP or identifier is ever a label.
type Metrics interface {
	// MailProcessed records one delivery attempt: how long the job waited and how long
	// the send took (zero when nothing was sent).
	MailProcessed(class authflow.QuotaClass, outcome MailOutcome, queueDelay, sendDuration time.Duration)
	// RefreshReuseDetected counts a session revoked because a used token came back.
	RefreshReuseDetected()
}

// RequestMetrics records what the HTTP transport saw, for the alerts on failing sign-in. Labels come
// from closed sets: the route is the matched pattern, never the path, and operation and reason are
// the short codes of the use cases. No email, IP, token or identifier is ever a label.
type RequestMetrics interface {
	// RequestServed records one answered request.
	RequestServed(route string, status int, took time.Duration)
	// AuthDenied records an expected refusal of a proof or a quota: the operation that refused and why.
	AuthDenied(operation, reason string)
}

// OIDCMetrics records what happens to the tokens of API resources and to the rights over them. Labels come from closed
// sets: a resource is an identifier an operator registered (admitted up to a bound, "unknown" for one that is not), the
// outcome and the change are short codes of the use cases. No user, client secret, token or scope is ever a label.
type OIDCMetrics interface {
	// ResourceToken records a token request that named a resource: issued, or the error code it was refused with.
	ResourceToken(resource, outcome string)
	// PermissionChange records a change of the rights over a resource, or a grant ended by a person, with the number of
	// grants it ended.
	PermissionChange(change string, grantsEnded int)
	// Introspection records an answer to an API that asked about a token: active, inactive, or refused (the API itself
	// could not be authenticated).
	Introspection(resource, outcome string)
}
