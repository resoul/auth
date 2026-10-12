package oidc

import "time"

// AuthorizationCode is the one-time proof a browser carries from the provider to a client. Exchanging it needs the
// client's own authentication and the PKCE verifier, so a code that leaks from a URL buys nothing alone.
type AuthorizationCode struct {
	Hash          SecretHash
	GrantID       string
	RedirectURI   string
	CodeChallenge string
	Nonce         string
	Scopes        []string
	// Resources are the APIs this authorization asked for; a token request may select one of them.
	Resources  []ResourceScopes
	AuthTime   time.Time
	AMR        []string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	ConsumedAt time.Time
}

// Exchange checks the code against what the client presents and marks it consumed. A consumed code is a replay: the
// caller revokes the grant and keeps that revocation. Which check failed is for logs and the audit trail, never for
// the client.
func (c *AuthorizationCode) Exchange(now time.Time, redirectURI, verifier string) error {
	if !c.ConsumedAt.IsZero() {
		return ErrCodeReplayed
	}
	if !now.Before(c.ExpiresAt) {
		return ErrCodeExpired
	}
	if redirectURI != c.RedirectURI {
		return ErrRedirectMismatch
	}
	if !VerifyPKCE(c.CodeChallenge, verifier) {
		return ErrPKCE
	}
	c.ConsumedAt = now.UTC()
	return nil
}

// Matches reports whether the redirect URI and the verifier are those of the code, whatever its age or state. A used code
// is presented again to find out whether the one presenting it could have been the first: the time that has passed since
// does not change that, so a copy kept past the expiry still ends the grant it was spent on.
func (c *AuthorizationCode) Matches(redirectURI, verifier string) bool {
	return redirectURI == c.RedirectURI && VerifyPKCE(c.CodeChallenge, verifier)
}

// RefreshToken is one link of a grant's chain. Each is exchanged once, for its single successor; exchanged again, it
// is a replay and the whole grant is revoked.
type RefreshToken struct {
	ID        string
	GrantID   string
	Hash      SecretHash
	ParentID  string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    time.Time
	RevokedAt time.Time
}

// Exchange marks the token used if it may be exchanged now. A used token yields ErrRefreshReplayed.
func (t *RefreshToken) Exchange(now time.Time) error {
	switch {
	case !t.RevokedAt.IsZero():
		return ErrRefreshRevoked
	case !t.UsedAt.IsZero():
		return ErrRefreshReplayed
	case !now.Before(t.ExpiresAt):
		return ErrRefreshExpired
	}
	t.UsedAt = now.UTC()
	return nil
}

// RefreshExpiry returns when a token created at now ends: after the idle time, and never after the grant.
func RefreshExpiry(now time.Time, p Policy, g *Grant) time.Time {
	end := now.Add(p.RefreshIdle)
	if g.ExpiresAt.Before(end) {
		end = g.ExpiresAt
	}
	return end
}
