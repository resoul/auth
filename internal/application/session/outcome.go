package session

// Outcome is the externally visible result class of a use case. Transports map a
// denial to one public response; Reason is only for audit and tests.
type Outcome string

// Outcomes.
const (
	// OutcomeOK means the operation happened.
	OutcomeOK Outcome = "ok"
	// OutcomeDenied is an expected refusal. Refresh refusals all look alike to clients.
	OutcomeDenied Outcome = "denied"
)

// Reason says why a request was refused. It must not reach clients.
type Reason string

// Reasons.
const (
	ReasonMalformed       Reason = "malformed"
	ReasonInvalidToken    Reason = "invalid_token"
	ReasonUnknownToken    Reason = "unknown_token"
	ReasonUnknownSession  Reason = "unknown_session"
	ReasonSessionInactive Reason = "session_inactive"
	ReasonTokenReused     Reason = "token_reused"
	ReasonTokenRevoked    Reason = "token_revoked"
	ReasonTokenExpired    Reason = "token_expired"
)
