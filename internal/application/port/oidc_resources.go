package port

import (
	"context"
	"errors"
	"time"

	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/domain/oidc"
)

// ErrResourceExists reports a registration whose identifier, resource URI or audience belongs to another resource.
var ErrResourceExists = errors.New("resource already exists")

// OIDCResourceRepository stores the API resources and what each client may ask of them.
//
// Locks. Everything that issues a token for a resource, and everything that changes the rights over one, takes the
// resource row first (ByURIsForShare, or GetForUpdate), before any user or grant. That order is what makes a change
// final: once it has committed, no token is being issued under the rights it took away.
type OIDCResourceRepository interface {
	// Create stores a resource. It returns ErrResourceExists when the ID, the URI or the audience is taken.
	Create(ctx context.Context, r *oidc.Resource) error
	// Get loads a resource without a lock. It returns ErrNotFound.
	Get(ctx context.Context, id string) (*oidc.Resource, error)
	// GetForUpdate loads a resource and locks it exclusively. It returns ErrNotFound.
	GetForUpdate(ctx context.Context, id string) (*oidc.Resource, error)
	// ByURIsForShare loads the resources registered under the URIs and locks them shared, in the order of their IDs.
	// A URI that names no resource is simply not in the result.
	ByURIsForShare(ctx context.Context, uris []string) ([]*oidc.Resource, error)
	// ByIDsForShare is ByURIsForShare for identifiers: the resources of a request that waited for a sign-in.
	ByIDsForShare(ctx context.Context, ids []string) ([]*oidc.Resource, error)
	// List returns every resource, by ID.
	List(ctx context.Context) ([]*oidc.Resource, error)
	// SetStatus enables or disables a resource and raises its policy version. It returns ErrNotFound. The grants are not
	// touched: the use case ends them in the same transaction.
	SetStatus(ctx context.Context, id, status string, now time.Time) error
	// SetScopes replaces the scopes a resource defines and raises its policy version. It returns ErrNotFound.
	SetScopes(ctx context.Context, id string, scopes []string, now time.Time) error
	// AudienceTaken reports whether a resource has the audience.
	AudienceTaken(ctx context.Context, audience string) (bool, error)

	// RotateSecret adds an introspection secret to the resource. The secrets live until now stay valid for overlap more
	// (none when it is zero), then end. It returns ErrNotFound and ErrOIDCSecretCollision.
	RotateSecret(ctx context.Context, resourceID, secretID string, secret oidc.SecretHash, now time.Time, overlap time.Duration) error
	// SecretValid reports whether the secret is one of the resource's live secrets: not revoked, not past its end.
	SecretValid(ctx context.Context, resourceID string, secret oidc.SecretHash, now time.Time) (bool, error)

	// ClientScopes returns, for each of the resources, the scopes the client may ask of it; a resource the client has no
	// right to is not in the map.
	ClientScopes(ctx context.Context, clientID string, resourceIDs []string) (map[string][]string, error)
	// ClientResources lists what a client may ask of each resource, by resource ID.
	ClientResources(ctx context.Context, clientID string) ([]oidc.ClientResource, error)
	// ResourceClients lists the clients that may ask of a resource, by client ID.
	ResourceClients(ctx context.Context, resourceID string) ([]oidc.ClientResource, error)
	// SetClientScopes allows the client the scopes of the resource, replacing what it had, and returns what it had. The
	// caller holds the resource exclusively (GetForUpdate).
	SetClientScopes(ctx context.Context, clientID, resourceID string, scopes []string, now time.Time) (previous []string, err error)
	// DeleteClientScopes takes every right of the resource from the client and returns what it had; nothing is not an
	// error. The caller holds the resource exclusively.
	DeleteClientScopes(ctx context.Context, clientID, resourceID string) (previous []string, err error)
}

// AppResource is what a grant holds of one resource, as a person sees it.
type AppResource struct {
	ID     string
	Name   string
	Scopes []string
}

// AppGrant is one live grant of a user, for the list of the applications they connected.
type AppGrant struct {
	ID         string
	ClientID   string
	ClientName string
	// Scopes are the protocol scopes (openid, email); the rights of APIs are in Resources.
	Scopes     []string
	Resources  []AppResource
	CreatedAt  time.Time
	LastUsedAt time.Time
	ExpiresAt  time.Time
}

// OIDCAppRepository reads and ends what a user has connected. Everything is bound to the user whose ID is passed, so a
// grant of another user is never shown or ended.
type OIDCAppRepository interface {
	// LiveGrantsOfUser lists the user's live grants whose sign-in is live, applications by name and newest use first,
	// at most 200.
	LiveGrantsOfUser(ctx context.Context, userID identity.UserID, now time.Time) ([]AppGrant, error)
	// RevokeOwned ends one grant of the user, with its refresh tokens, and queues the back-channel notice of its
	// client, in the order every statement locks (the user shared, then the grant). It reports whether a live grant of
	// the user was ended; a grant that is missing, ended or someone else's is false and changes nothing.
	RevokeOwned(ctx context.Context, userID identity.UserID, grantID string, now time.Time) (ended bool, clientID string, err error)
	// RevokeOwnedOfClient does the same for every live grant of the user held by the client, and returns how many ended.
	RevokeOwnedOfClient(ctx context.Context, userID identity.UserID, clientID string, now time.Time) (int, error)
	// RevokeOfResource ends the live grants that hold the resource: those of one client when clientID is not empty,
	// those that hold at least one of scopes when scopes is not nil. It queues their notices. The caller holds the
	// resource exclusively. It returns how many grants ended.
	RevokeOfResource(ctx context.Context, resourceID, clientID string, scopes []string, now time.Time) (int, error)
}
