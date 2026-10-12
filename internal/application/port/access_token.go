package port

import (
	"errors"
	"time"

	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/domain/session"
)

// ErrInvalidAccessToken reports a token that must not authenticate anyone: bad
// signature, algorithm, key, issuer, audience, time bounds or claims. The reason is
// in the wrapped message and must not reach clients.
var ErrInvalidAccessToken = errors.New("invalid access token")

// AccessClaims are the facts an access token states: who, which session, how they
// signed in. IssuedAt and ExpiresAt are set by the verifier; the signer chooses its own.
// Every time is in UTC.
type AccessClaims struct {
	UserID    identity.UserID
	SessionID session.ID
	AuthTime  time.Time
	AMR       []string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// AccessToken is a signed token and the time it stops being valid.
type AccessToken struct {
	Value     string
	ExpiresAt time.Time
}

// AccessSigner issues access tokens. Use cases sign before the transaction commits,
// so a signing failure rolls the change back.
type AccessSigner interface {
	SignAccess(c AccessClaims) (AccessToken, error)
}

// AccessVerifier checks a presented access token. It verifies the signature and the
// claims only; whether the session is still alive is a separate check in the store.
type AccessVerifier interface {
	// VerifyAccess returns the claims or an error wrapping ErrInvalidAccessToken.
	VerifyAccess(token string) (AccessClaims, error)
}

// JWKSPublisher returns the public key set that services use to verify tokens.
type JWKSPublisher interface {
	// JWKS returns the JSON Web Key Set document: public keys only.
	JWKS() ([]byte, error)
}
