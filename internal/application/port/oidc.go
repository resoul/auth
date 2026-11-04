package port

import (
	"context"
	"errors"
	"time"

	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/oidc"
)

var (
	ErrClientExists        = errors.New("client already exists")
	ErrOIDCSecretCollision = errors.New("oidc secret hash collision")
	ErrRefreshConflict     = errors.New("refresh token already has a successor")
	ErrInvalidOIDCSecret   = errors.New("invalid oidc secret")
)

type OIDCSecrets interface {
	NewOIDCSecret() (secret string, hash oidc.SecretHash, err error)
	HashOIDCSecret(secret string) (oidc.SecretHash, error)
}

type OIDCIDGenerator interface {
	NewOIDCID() (string, error)
}

type OIDCClientRepository interface {
	Create(ctx context.Context, c *oidc.Client, secretID string, secret oidc.SecretHash) error
	Get(ctx context.Context, id string) (*oidc.Client, error)
	List(ctx context.Context) ([]*oidc.Client, error)
	SetStatus(ctx context.Context, id, status string, now time.Time) error
	RotateSecret(ctx context.Context, id, secretID string, secret oidc.SecretHash, now time.Time, overlap time.Duration) error
	SetLogout(ctx context.Context, id string, postLogout []string, backchannel string, now time.Time) error
	SecretValid(ctx context.Context, id string, secret oidc.SecretHash, now time.Time) (bool, error)
}

type OIDCRequestRepository interface {
	Create(ctx context.Context, r *oidc.AuthorizationRequest) error
	GetForUpdate(ctx context.Context, id oidc.SecretHash) (*oidc.AuthorizationRequest, error)
	Complete(ctx context.Context, id oidc.SecretHash, now time.Time) error
}

type OIDCSessionRepository interface {
	Create(ctx context.Context, s *oidc.OPSession) error
	GetBySecret(ctx context.Context, secret oidc.SecretHash) (*oidc.OPSession, error)
	Get(ctx context.Context, id string) (*oidc.OPSession, error)
	Touch(ctx context.Context, id string, now time.Time) error
	RevokeAllForUser(ctx context.Context, userID identity.UserID, now time.Time) error
	RevokeOthersForUser(ctx context.Context, userID identity.UserID, keep string, now time.Time) error
	End(ctx context.Context, id string, now time.Time) error
}

type OIDCGrantRepository interface {
	FindLive(ctx context.Context, clientID, opSessionID string) (*oidc.Grant, error)
	Create(ctx context.Context, g *oidc.Grant) error
	Get(ctx context.Context, id string) (*oidc.Grant, error)
	Touch(ctx context.Context, id string, now time.Time) error
	Revoke(ctx context.Context, id string, now time.Time) error
	RevokeAllForClient(ctx context.Context, clientID string, now time.Time) error
}

type OIDCCodeRepository interface {
	Create(ctx context.Context, c *oidc.AuthorizationCode) error
	GetByHashForUpdate(ctx context.Context, hash oidc.SecretHash) (*oidc.AuthorizationCode, *oidc.Grant, error)
	Consume(ctx context.Context, c *oidc.AuthorizationCode) error
}

type OIDCRefreshRepository interface {
	Create(ctx context.Context, t *oidc.RefreshToken) error
	GetByHashForUpdate(ctx context.Context, hash oidc.SecretHash) (*oidc.RefreshToken, *oidc.Grant, error)
	MarkUsed(ctx context.Context, t *oidc.RefreshToken) error
	Successor(ctx context.Context, parentID string) (*oidc.RefreshToken, error)
	Supersede(ctx context.Context, t *oidc.RefreshToken, now time.Time) error
}

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

type OIDCLogoutRepository interface {
	Claim(ctx context.Context, now, leaseUntil time.Time) (*ClaimedLogout, error)
	Complete(ctx context.Context, id string) error
	Retry(ctx context.Context, id string, availableAt time.Time, reason string) error
	Abandon(ctx context.Context, id string, reason string) error
	Enqueue(ctx context.Context, id, clientID string, userID identity.UserID, sessionID string, now, expiresAt time.Time) error
}
