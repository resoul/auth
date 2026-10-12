package port

import (
	"context"
	"errors"
	"time"

	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/domain/oidc"
)

// Errors of the OpenID Provider repositories.
var (
	// ErrClientExists reports a registration of a client ID that is taken.
	ErrClientExists = errors.New("client already exists")
	// ErrOIDCSecretCollision reports a secret hash that already exists; a random 256-bit value never repeats, so it
	// means a bug or a replayed insert.
	ErrOIDCSecretCollision = errors.New("oidc secret hash collision")
	// ErrRefreshConflict reports a second successor of one refresh token: two exchanges raced past the lock.
	ErrRefreshConflict = errors.New("refresh token already has a successor")
	// ErrInvalidOIDCSecret reports a secret of the wrong shape; nothing was compared.
	ErrInvalidOIDCSecret = errors.New("invalid oidc secret")
)

// OIDCSecrets makes and hashes the random secrets of the provider: client secrets, request ids, cookies, codes and
// refresh tokens. All are 256 bits, shown once, and stored as their SHA-256.
type OIDCSecrets interface {
	// NewOIDCSecret returns a fresh secret and its hash.
	NewOIDCSecret() (secret string, hash oidc.SecretHash, err error)
	// HashOIDCSecret hashes a presented secret. It returns ErrInvalidOIDCSecret for the wrong shape.
	HashOIDCSecret(secret string) (oidc.SecretHash, error)
}

// OIDCIDGenerator creates row identifiers (UUIDv7, as text) of OP sessions, grants, refresh tokens and secrets.
type OIDCIDGenerator interface {
	NewOIDCID() (string, error)
}

// OIDCClientRepository stores registered clients and their secrets.
type OIDCClientRepository interface {
	// Create stores a client with its first secret. It returns ErrClientExists.
	Create(ctx context.Context, c *oidc.Client, secretID string, secret oidc.SecretHash) error
	// Get loads a client. It returns ErrNotFound.
	Get(ctx context.Context, id string) (*oidc.Client, error)
	// List returns every client, by ID.
	List(ctx context.Context) ([]*oidc.Client, error)
	// SetStatus enables or disables a client and raises its policy version. It returns ErrNotFound. It does not touch
	// the grants: the use case revokes them in the same transaction.
	SetStatus(ctx context.Context, id, status string, now time.Time) error
	// RotateSecret adds a new secret. The secrets valid until now stay valid for overlap more, then end, so a client
	// can be redeployed with the new one; older leftovers of a previous rotation end at once.
	RotateSecret(ctx context.Context, id, secretID string, secret oidc.SecretHash, now time.Time, overlap time.Duration) error
	// SetLogout stores the logout settings of a client and raises its policy version. It returns ErrNotFound.
	SetLogout(ctx context.Context, id string, postLogout []string, backchannel string, now time.Time) error
	// SecretValid reports whether the secret is one of the client's live secrets: not revoked, not past its end.
	SecretValid(ctx context.Context, id string, secret oidc.SecretHash, now time.Time) (bool, error)
}

// OIDCRequestRepository stores the authorization requests of browsers that are signing in.
type OIDCRequestRepository interface {
	Create(ctx context.Context, r *oidc.AuthorizationRequest) error
	// GetForUpdate loads a request by the hash of its id and keeps it locked. It returns ErrNotFound.
	GetForUpdate(ctx context.Context, id oidc.SecretHash) (*oidc.AuthorizationRequest, error)
	// Complete marks the request as used.
	Complete(ctx context.Context, id oidc.SecretHash, now time.Time) error
}

// OIDCSessionRepository stores the OP sessions, the sign-ins shared by the applications.
type OIDCSessionRepository interface {
	Create(ctx context.Context, s *oidc.OPSession) error
	// GetBySecret loads the session of a cookie, without a lock. It returns ErrNotFound.
	GetBySecret(ctx context.Context, secret oidc.SecretHash) (*oidc.OPSession, error)
	// Get loads a session by ID, without a lock. It returns ErrNotFound.
	Get(ctx context.Context, id string) (*oidc.OPSession, error)
	// Touch records the use of a session at now, for its idle time.
	Touch(ctx context.Context, id string, now time.Time) error
	// RevokeAllForUser ends every OP session of the user together with their grants and refresh tokens, and queues a
	// back-channel logout notice for every live grant whose client has an endpoint. It queues on the user row like
	// SessionRepository.RevokeAllForUser, so an exchange running at that moment is either seen and revoked, or finds
	// its grant revoked.
	RevokeAllForUser(ctx context.Context, userID identity.UserID, now time.Time) error
	// RevokeOthersForUser does the same for every OP session except the one that grew from the device session keep (the
	// zero ID keeps none). A key deleted or an address moved cuts off the other devices, and what they opened with the
	// provider goes with them.
	RevokeOthersForUser(ctx context.Context, userID identity.UserID, keep string, now time.Time) error
	// End ends one OP session in the same way: the session, its grants and refresh tokens, and the notices. A session
	// that is gone or already ended is not an error.
	End(ctx context.Context, id string, now time.Time) error
}

// OIDCGrantRepository stores the grants clients hold on OP sessions.
type OIDCGrantRepository interface {
	// FindLive returns the live grant of the client on the OP session, or ErrNotFound.
	FindLive(ctx context.Context, clientID, opSessionID string) (*oidc.Grant, error)
	Create(ctx context.Context, g *oidc.Grant) error
	// Get loads a grant without a lock. It returns ErrNotFound.
	Get(ctx context.Context, id string) (*oidc.Grant, error)
	// Touch records the use of a grant at now.
	Touch(ctx context.Context, id string, now time.Time) error
	// Revoke ends the grant and its refresh tokens. A missing or ended grant is not an error.
	Revoke(ctx context.Context, id string, now time.Time) error
	// RevokeAllForClient ends every grant of the client, for disabling it.
	RevokeAllForClient(ctx context.Context, clientID string, now time.Time) error
}

// OIDCCodeRepository stores authorization codes.
type OIDCCodeRepository interface {
	Create(ctx context.Context, c *oidc.AuthorizationCode) error
	// GetByHashForUpdate loads a code and keeps it locked. It first share-locks the user and locks the grant, in the
	// order every statement that ends or issues access uses, and returns the grant with the code. It returns
	// ErrNotFound.
	GetByHashForUpdate(ctx context.Context, hash oidc.SecretHash) (*oidc.AuthorizationCode, *oidc.Grant, error)
	// Consume stores the consumption of a code loaded by GetByHashForUpdate.
	Consume(ctx context.Context, c *oidc.AuthorizationCode) error
}

// OIDCRefreshRepository stores the refresh tokens of grants.
type OIDCRefreshRepository interface {
	// Create stores a token. It returns ErrRefreshConflict when its parent already has a successor.
	Create(ctx context.Context, t *oidc.RefreshToken) error
	// GetByHashForUpdate loads a token, locking the user (shared), the grant and the token in that order, and returns
	// the grant with it. It returns ErrNotFound.
	GetByHashForUpdate(ctx context.Context, hash oidc.SecretHash) (*oidc.RefreshToken, *oidc.Grant, error)
	// MarkUsed stores that a token loaded by GetByHashForUpdate was exchanged.
	MarkUsed(ctx context.Context, t *oidc.RefreshToken) error
}

// ClaimedLogout is a logout notice a delivery worker holds a lease on. BackchannelURI is the client's current endpoint:
// empty when the client was disabled or lost it since, and the worker then gives the notice up.
type ClaimedLogout struct {
	ID             string
	ClientID       string
	BackchannelURI string
	UserID         identity.UserID
	SessionID      string
	Attempts       int
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

// OIDCLogoutRepository is the queue of back-channel logout notices. The use cases that end a sign-in queue them through
// OIDCSessionRepository, in the transaction that revokes; this side only hands them to a delivery worker.
type OIDCLogoutRepository interface {
	// Claim leases one due notice until leaseUntil and counts the attempt; SKIP LOCKED passes over a notice another
	// worker is claiming, and an expired lease makes a notice claimable again. It returns ErrNotFound when none is due.
	Claim(ctx context.Context, now, leaseUntil time.Time) (*ClaimedLogout, error)
	// Complete marks a notice delivered.
	Complete(ctx context.Context, id string) error
	// Retry puts a notice back for availableAt, with a short reason code.
	Retry(ctx context.Context, id string, availableAt time.Time, reason string) error
	// Abandon gives a notice up, with a short reason code.
	Abandon(ctx context.Context, id string, reason string) error
	// Enqueue is for tests and tools: it queues a notice as the revocation does.
	Enqueue(ctx context.Context, id, clientID string, userID identity.UserID, sessionID string, now, expiresAt time.Time) error
}
