package oidc

import (
	"time"

	"go.airlance.org/auth/internal/domain/identity"
)

// OPSession is the sign-in shared by every application: proved once, remembered by a cookie of the auth host only. It
// is not the device session of the /v1 API, and ending one does not end the other.
type OPSession struct {
	ID         string
	UserID     identity.UserID
	SecretHash SecretHash
	// AuthTime is when the user really authenticated and AMR how; every ID Token of the session repeats them.
	AuthTime   time.Time
	AMR        []string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	RevokedAt  time.Time
	// DeviceSessionID is the session of the /v1 API whose proof opened this sign-in; empty if it is gone.
	DeviceSessionID string
}

// Active reports whether the session may still sign users in: not revoked, within its absolute time and not idle.
func (s *OPSession) Active(now time.Time, p Policy) bool {
	return s.RevokedAt.IsZero() && now.Before(s.ExpiresAt) && now.Before(s.LastSeenAt.Add(p.OPSessionIdle))
}

// Grant is what one client may do for one user on one OP session. Its refresh tokens belong to it, so ending it ends
// them, and it never outlives its OP session.
type Grant struct {
	ID          string
	ClientID    string
	UserID      identity.UserID
	OPSessionID string
	// Scopes are the protocol scopes (openid, email); the rights of APIs are in Resources.
	Scopes []string
	// Resources are the APIs agreed with this grant and the rights held of each. A grant never gains one later: asking
	// for more is a new authorization.
	Resources     []ResourceScopes
	PolicyVersion int
	CreatedAt     time.Time
	LastUsedAt    time.Time
	ExpiresAt     time.Time
	RevokedAt     time.Time
}

// Active reports whether the grant is live: not revoked and within its time.
func (g *Grant) Active(now time.Time) bool { return g.RevokedAt.IsZero() && now.Before(g.ExpiresAt) }

// GrantExpiry returns when a new grant ends: after the absolute refresh time, and never after the OP session.
func GrantExpiry(now time.Time, p Policy, session *OPSession) time.Time {
	end := now.Add(p.RefreshAbsolute)
	if session.ExpiresAt.Before(end) {
		end = session.ExpiresAt
	}

	return end
}

// Resource returns what the grant holds of the resource, or nil.
func (g *Grant) Resource(resourceID string) *ResourceScopes {
	return FindResource(g.Resources, resourceID)
}
