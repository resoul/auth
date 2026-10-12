// Package oidc holds the rules of the OpenID Provider: clients, authorization requests, the shared sign-in
// (OP session), grants, one-time codes and rotating refresh tokens. It knows nothing of HTTP, SQL or JWT.
package oidc

import (
	"errors"
	"time"
)

// Policy holds the lifetimes. They are the project's own decisions, not requirements of OpenID Connect.
type Policy struct {
	// RequestTTL is how long a browser has to sign in for one authorization request.
	RequestTTL time.Duration
	// CodeTTL is the life of an authorization code.
	CodeTTL time.Duration
	// IDTokenTTL and AccessTTL are the lives of the tokens a client holds. Neither is the life of the client's own
	// session: the client sets that itself and ends it when it learns the grant is gone.
	IDTokenTTL time.Duration
	AccessTTL  time.Duration
	// OPSessionIdle ends a sign-in that was not used for this long; OPSessionAbsolute ends it whatever its use.
	OPSessionIdle     time.Duration
	OPSessionAbsolute time.Duration
	// RefreshIdle is the life of one refresh token, renewed by each rotation; RefreshAbsolute is the life of the
	// whole grant. Neither outlasts the OP session.
	RefreshIdle     time.Duration
	RefreshAbsolute time.Duration
}

// LogoutNoticeTTL is how long a back-channel logout notice is retried before it is given up: the client's own session has
// outlived its usefulness by then, and an access token it holds expired long before.
const LogoutNoticeTTL = 24 * time.Hour

// DefaultPolicy returns the lifetimes of the first version.
func DefaultPolicy() Policy {
	return Policy{
		RequestTTL: 10 * time.Minute, CodeTTL: 60 * time.Second,
		IDTokenTTL: 5 * time.Minute, AccessTTL: 5 * time.Minute,
		OPSessionIdle: 24 * time.Hour, OPSessionAbsolute: 7 * 24 * time.Hour,
		RefreshIdle: 30 * 24 * time.Hour, RefreshAbsolute: 90 * 24 * time.Hour,
	}
}

// Validate refuses a policy that cannot work.
func (p Policy) Validate() error {
	for _, d := range []time.Duration{p.RequestTTL, p.CodeTTL, p.IDTokenTTL, p.AccessTTL, p.OPSessionIdle, p.OPSessionAbsolute, p.RefreshIdle, p.RefreshAbsolute} {
		if d <= 0 {
			return errors.New("oidc policy: every lifetime must be positive")
		}
	}
	if p.OPSessionIdle > p.OPSessionAbsolute {
		return errors.New("oidc policy: the idle time of an OP session cannot exceed its absolute time")
	}
	return nil
}
