package oidc

import (
	"errors"
	"time"
)

// SecretHash is the SHA-256 of a random 256-bit secret: a client secret, a request id, a cookie, a code or a refresh
// token. Only the hash is stored.
type SecretHash [32]byte

// Bytes returns the hash as a slice, for storage.
func (h SecretHash) Bytes() []byte { return h[:] }

// IsZero reports whether the hash is unset.
func (h SecretHash) IsZero() bool { return h == SecretHash{} }

// SecretHashFrom reads a stored hash.
func SecretHashFrom(b []byte) (SecretHash, error) {
	var h SecretHash
	if len(b) != len(h) {
		return h, errors.New("oidc: a stored secret hash must be 32 bytes")
	}
	copy(h[:], b)
	return h, nil
}

// AuthorizationRequest is what a browser asked for at /authorize, kept on the server while the user signs in. The
// page that signs the user in sees only its opaque id, and the request answers only to the browser holding the
// cookie whose hash is Binding.
type AuthorizationRequest struct {
	// ID is the hash of the opaque id the sign-in page carries.
	ID          SecretHash
	Binding     SecretHash
	ClientID    string
	RedirectURI string
	Scopes      []string
	// Resources are the APIs asked for, with the rights agreed for each when the request was made.
	Resources     []ResourceScopes
	State         string
	Nonce         string
	CodeChallenge string
	// FreshLogin means prompt=login or max_age=0: only an authentication after CreatedAt will do.
	FreshLogin bool
	// MaxAge is the largest age, in seconds, of the authentication the client accepts; nil means any.
	MaxAge      *int
	CreatedAt   time.Time
	ExpiresAt   time.Time
	CompletedAt time.Time
}

// Usable reports whether the browser holding binding may still use the request at now.
func (r *AuthorizationRequest) Usable(now time.Time, binding SecretHash) bool {
	return r.Binding == binding && r.CompletedAt.IsZero() && now.Before(r.ExpiresAt)
}

// Satisfied reports whether an authentication made at authTime meets the request: after the request began when a
// fresh login is demanded, and within max_age when the client set one. The age is that of the authentication, not
// of the last refresh.
func (r *AuthorizationRequest) Satisfied(authTime, now time.Time) bool {
	zero := r.MaxAge != nil && *r.MaxAge == 0
	if (r.FreshLogin || zero) && authTime.Before(r.CreatedAt) {
		return false
	}
	// max_age=0 is a demand for a fresh login, which the check above makes; read as an age of zero it would refuse
	// every login, since the time of an authentication is never the instant it is checked.
	if r.MaxAge != nil && !zero && now.Sub(authTime) > time.Duration(*r.MaxAge)*time.Second {
		return false
	}
	return true
}
