package oidc

import "time"

type AuthorizationCode struct {
	Hash          SecretHash
	GrantID       string
	RedirectURI   string
	CodeChallenge string
	Nonce         string
	Scopes        []string
	Resources     []ResourceScopes
	AuthTime      time.Time
	AMR           []string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	ConsumedAt    time.Time
}

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

func (c *AuthorizationCode) Matches(redirectURI, verifier string) bool {
	return redirectURI == c.RedirectURI && VerifyPKCE(c.CodeChallenge, verifier)
}

type RefreshToken struct {
	ID           string
	GrantID      string
	Hash         SecretHash
	ParentID     string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	UsedAt       time.Time
	RevokedAt    time.Time
	SupersededAt time.Time
}

const RefreshRetryWindow = 30 * time.Second

func (t *RefreshToken) Exchange(now time.Time) error {
	switch {
	case !t.RevokedAt.IsZero():
		return ErrRefreshRevoked
	case !t.UsedAt.IsZero() || !t.SupersededAt.IsZero():
		return ErrRefreshReplayed
	case !now.Before(t.ExpiresAt):
		return ErrRefreshExpired
	}

	t.UsedAt = now.UTC()

	return nil
}

func (t *RefreshToken) MayRetry(now time.Time) bool {
	return !t.UsedAt.IsZero() && t.SupersededAt.IsZero() && now.Sub(t.UsedAt) <= RefreshRetryWindow && now.Before(t.ExpiresAt)
}

func RefreshExpiry(now time.Time, p Policy, g *Grant) time.Time {
	end := now.Add(p.RefreshIdle)
	if g.ExpiresAt.Before(end) {
		end = g.ExpiresAt
	}

	return end
}
