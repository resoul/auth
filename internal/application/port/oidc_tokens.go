package port

import (
	"errors"
	"time"

	"airlance.org/auth/internal/domain/identity"
)

// ErrInvalidOIDCToken reports an OpenID Connect token that must not be believed: bad signature, algorithm, key,
// type, issuer, audience, time bounds or claims. The reason is in the wrapped message and must not reach clients.
var ErrInvalidOIDCToken = errors.New("invalid oidc token")

// IDTokenClaims are what an ID Token tells one relying party about one sign-in. Email and its verification are
// set only when the grant carries the email scope.
type IDTokenClaims struct {
	Subject  identity.UserID
	ClientID string
	// Nonce is the value the relying party sent; it binds the token to that request.
	Nonce string
	// AuthTime is when the user actually authenticated, not when the token was issued.
	AuthTime time.Time
	AMR      []string
	// SessionID is the OP session (sid), for logout; it is not a secret.
	SessionID     string
	IncludeEmail  bool
	Email         string
	EmailVerified bool
}

// OIDCAccessClaims are the facts of an access token for one resource. The token is for exactly one audience.
type OIDCAccessClaims struct {
	Subject   identity.UserID
	ClientID  string
	Audience  string
	Scope     []string
	SessionID string
	GrantID   string
	AuthTime  time.Time
	// JTI is chosen by the signer; the verifier reports the token's.
	JTI       string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// ServiceAccessClaims are the facts of an access token of a service identity (the client_credentials grant): the client
// is its own subject, and there is no user, sign-in or grant behind it. The token is for exactly one audience.
type ServiceAccessClaims struct {
	ClientID  string
	Audience  string
	Scope     []string
	JTI       string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// LogoutClaims are what a logout token tells a client: this user's sign-in, under this sid, ended. The jti is the id of
// the queued notice, so a repeated delivery carries the same one.
type LogoutClaims struct {
	Subject   identity.UserID
	ClientID  string
	SessionID string
	JTI       string
}

// IDTokenHint is what a presented ID token says, after its signature was checked. It may be long expired: a client sends
// the last ID token it has to name the sign-in to end, and an expired one still names it.
type IDTokenHint struct {
	Subject   identity.UserID
	ClientID  string
	SessionID string
}

// OIDCSigner issues the tokens of the OpenID Provider. Each kind has its own method and its own type header, so
// one cannot be issued, or accepted, in place of another.
type OIDCSigner interface {
	SignIDToken(c IDTokenClaims) (AccessToken, error)
	SignOIDCAccessToken(c OIDCAccessClaims) (AccessToken, OIDCAccessClaims, error)
	// SignServiceToken issues the access token of a service for one audience (RFC 9068, sub = client_id) and returns the
	// claims it made, the jti included.
	SignServiceToken(c ServiceAccessClaims) (AccessToken, ServiceAccessClaims, error)
	// SignLogoutToken issues the token of a back-channel logout notice (typ logout+jwt, no nonce).
	SignLogoutToken(c LogoutClaims) (AccessToken, error)
}

// OIDCAccessVerifier checks an access token presented to this provider (UserInfo). It verifies signature and claims
// only; whether the grant is still alive is a separate check in the store.
type OIDCAccessVerifier interface {
	// VerifyOIDCAccess returns the claims or an error wrapping ErrInvalidOIDCToken. The audience must be the one given.
	VerifyOIDCAccess(token, audience string) (OIDCAccessClaims, error)
	// VerifyServiceAccess is VerifyOIDCAccess for the token of a service: the same checks of signature, type, issuer,
	// audience and time, and the claims of a service (sub equal to client_id, no sid, grant or auth_time). A token of a user
	// is refused here, and one of a service by VerifyOIDCAccess.
	VerifyServiceAccess(token, audience string) (ServiceAccessClaims, error)
	// VerifyIDTokenHint checks that an ID token was issued by this provider (signature, algorithm, type, issuer, one
	// audience) and returns what it names. It does not check the expiry. It returns an error wrapping ErrInvalidOIDCToken.
	VerifyIDTokenHint(token string) (IDTokenHint, error)
}
