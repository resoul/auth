package oidc

import "errors"

// Denials of the lifecycle. Each one is an expected refusal, not a failure.
var (
	// ErrInvalidClientID reports a client identifier outside the allowed shape.
	ErrInvalidClientID = errors.New("invalid client id")
	// ErrInvalidClient reports a client registration that cannot be stored.
	ErrInvalidClient = errors.New("invalid client")
	// ErrInvalidScope reports a scope the client or the provider does not offer.
	ErrInvalidScope = errors.New("invalid scope")
	// ErrInvalidResourceID reports a resource identifier outside the allowed shape.
	ErrInvalidResourceID = errors.New("invalid resource id")
	// ErrInvalidResource reports a resource registration that cannot be stored.
	ErrInvalidResource = errors.New("invalid resource")
	// ErrInvalidTarget reports a resource that is malformed, unknown, disabled or not open to the client.
	ErrInvalidTarget = errors.New("invalid target")
	// ErrCodeExpired means the authorization code's lifetime ended.
	ErrCodeExpired = errors.New("authorization code expired")
	// ErrCodeReplayed means the code was already exchanged.
	ErrCodeReplayed = errors.New("authorization code already used")
	// ErrRedirectMismatch means the redirect URI of the exchange is not the one of the request.
	ErrRedirectMismatch = errors.New("redirect uri does not match")
	// ErrPKCE means the code verifier does not match the challenge.
	ErrPKCE = errors.New("code verifier does not match the challenge")
	// ErrRefreshReplayed means the refresh token was already exchanged: someone holds a copy.
	ErrRefreshReplayed = errors.New("refresh token already used")
	// ErrRefreshRevoked means the refresh token was revoked.
	ErrRefreshRevoked = errors.New("refresh token revoked")
	// ErrRefreshExpired means the refresh token's lifetime ended.
	ErrRefreshExpired = errors.New("refresh token expired")
)
