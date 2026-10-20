package memory

import (
	"context"
	"errors"
	"time"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/oidc"
)

// errNoOIDC is what every OpenID Provider repository answers here. The provider's rules are about row locks and
// concurrent exchanges, which a store that runs one transaction at a time cannot show; its tests run on PostgreSQL.
// Only the revocation hook is real, as a no-op, because use cases of the /v1 API call it.
var errNoOIDC = errors.New("the in-memory store does not hold the OpenID Provider's data: use PostgreSQL")

func (s *Store) oidcStores() port.OIDCStores {
	return port.OIDCStores{
		OIDCClients: noClients{}, OIDCRequests: noRequests{}, OPSessions: noSessions{}, OIDCGrants: noGrants{}, OIDCCodes: noCodes{}, OIDCRefresh: noRefresh{}, OIDCLogout: noLogout{},
		OIDCResources: noResources{}, OIDCApps: noApps{},
	}
}

type noClients struct{}

func (noClients) Create(context.Context, *oidc.Client, string, oidc.SecretHash) error {
	return errNoOIDC
}
func (noClients) Get(context.Context, string) (*oidc.Client, error) {
	return nil, errNoOIDC
}

func (noClients) List(context.Context) ([]*oidc.Client, error) {
	return nil, errNoOIDC
}

func (noClients) SetStatus(context.Context, string, string, time.Time) error {
	return errNoOIDC
}

func (noClients) RotateSecret(context.Context, string, string, oidc.SecretHash, time.Time, time.Duration) error {
	return errNoOIDC
}
func (noClients) SetLogout(context.Context, string, []string, string, time.Time) error {
	return errNoOIDC
}
func (noClients) SecretValid(context.Context, string, oidc.SecretHash, time.Time) (bool, error) {
	return false, errNoOIDC
}

type noRequests struct{}

func (noRequests) Create(context.Context, *oidc.AuthorizationRequest) error {
	return errNoOIDC
}

func (noRequests) GetForUpdate(context.Context, oidc.SecretHash) (*oidc.AuthorizationRequest, error) {
	return nil, errNoOIDC
}
func (noRequests) Complete(context.Context, oidc.SecretHash, time.Time) error {
	return errNoOIDC
}

type noSessions struct{}

func (noSessions) Create(context.Context, *oidc.OPSession) error {
	return errNoOIDC
}

func (noSessions) GetBySecret(context.Context, oidc.SecretHash) (*oidc.OPSession, error) {
	return nil, errNoOIDC
}
func (noSessions) Get(context.Context, string) (*oidc.OPSession, error) {
	return nil, errNoOIDC
}

func (noSessions) Touch(context.Context, string, time.Time) error {
	return errNoOIDC
}

// RevokeAllForUser and End have nothing to revoke: no OP session exists here.
func (noSessions) RevokeAllForUser(context.Context, identity.UserID, time.Time) error {
	return nil
}

func (noSessions) End(context.Context, string, time.Time) error {
	return nil
}

func (noSessions) RevokeOthersForUser(context.Context, identity.UserID, string, time.Time) error {
	return nil
}

type noGrants struct{}

func (noGrants) FindLive(context.Context, string, string) (*oidc.Grant, error) {
	return nil, errNoOIDC
}

func (noGrants) Create(context.Context, *oidc.Grant) error {
	return errNoOIDC
}

func (noGrants) Get(context.Context, string) (*oidc.Grant, error) {
	return nil, errNoOIDC
}

func (noGrants) Touch(context.Context, string, time.Time) error {
	return errNoOIDC
}

func (noGrants) Revoke(context.Context, string, time.Time) error {
	return errNoOIDC
}

func (noGrants) RevokeAllForClient(context.Context, string, time.Time) error {
	return errNoOIDC
}

type noCodes struct{}

func (noCodes) Create(context.Context, *oidc.AuthorizationCode) error {
	return errNoOIDC
}

func (noCodes) GetByHashForUpdate(context.Context, oidc.SecretHash) (*oidc.AuthorizationCode, *oidc.Grant, error) {
	return nil, nil, errNoOIDC
}
func (noCodes) Consume(context.Context, *oidc.AuthorizationCode) error {
	return errNoOIDC
}

type noRefresh struct{}

func (noRefresh) Create(context.Context, *oidc.RefreshToken) error {
	return errNoOIDC
}

func (noRefresh) GetByHashForUpdate(context.Context, oidc.SecretHash) (*oidc.RefreshToken, *oidc.Grant, error) {
	return nil, nil, errNoOIDC
}
func (noRefresh) MarkUsed(context.Context, *oidc.RefreshToken) error {
	return errNoOIDC
}

type noLogout struct{}

func (noLogout) Claim(context.Context, time.Time, time.Time) (*port.ClaimedLogout, error) {
	return nil, port.ErrNotFound
}
func (noLogout) Complete(context.Context, string) error {
	return errNoOIDC
}

func (noLogout) Retry(context.Context, string, time.Time, string) error {
	return errNoOIDC
}

func (noLogout) Abandon(context.Context, string, string) error {
	return errNoOIDC
}

func (noLogout) Enqueue(context.Context, string, string, identity.UserID, string, time.Time, time.Time) error {
	return errNoOIDC
}

type noResources struct{}

func (noResources) Create(context.Context, *oidc.Resource) error {
	return errNoOIDC
}

func (noResources) Get(context.Context, string) (*oidc.Resource, error) {
	return nil, errNoOIDC
}
func (noResources) GetForUpdate(context.Context, string) (*oidc.Resource, error) {
	return nil, errNoOIDC
}
func (noResources) ByURIsForShare(context.Context, []string) ([]*oidc.Resource, error) {
	return nil, errNoOIDC
}
func (noResources) ByIDsForShare(context.Context, []string) ([]*oidc.Resource, error) {
	return nil, errNoOIDC
}
func (noResources) List(context.Context) ([]*oidc.Resource, error) {
	return nil, errNoOIDC
}

func (noResources) SetStatus(context.Context, string, string, time.Time) error {
	return errNoOIDC
}

func (noResources) SetScopes(context.Context, string, []string, time.Time) error {
	return errNoOIDC
}

func (noResources) RotateSecret(context.Context, string, string, oidc.SecretHash, time.Time, time.Duration) error {
	return errNoOIDC
}
func (noResources) SecretValid(context.Context, string, oidc.SecretHash, time.Time) (bool, error) {
	return false, errNoOIDC
}
func (noResources) AudienceTaken(context.Context, string) (bool, error) {
	return false, errNoOIDC
}

func (noResources) ClientScopes(context.Context, string, []string) (map[string][]string, error) {
	return nil, errNoOIDC
}
func (noResources) ClientResources(context.Context, string) ([]oidc.ClientResource, error) {
	return nil, errNoOIDC
}
func (noResources) ResourceClients(context.Context, string) ([]oidc.ClientResource, error) {
	return nil, errNoOIDC
}
func (noResources) SetClientScopes(context.Context, string, string, []string, time.Time) ([]string, error) {
	return nil, errNoOIDC
}
func (noResources) DeleteClientScopes(context.Context, string, string) ([]string, error) {
	return nil, errNoOIDC
}

type noApps struct{}

// Nothing is connected here, so listing finds nothing and there is nothing to end.
func (noApps) LiveGrantsOfUser(context.Context, identity.UserID, time.Time) ([]port.AppGrant, error) {
	return nil, nil
}
func (noApps) RevokeOwned(context.Context, identity.UserID, string, time.Time) (bool, string, error) {
	return false, "", nil
}
func (noApps) RevokeOwnedOfClient(context.Context, identity.UserID, string, time.Time) (int, error) {
	return 0, nil
}
func (noApps) RevokeOfResource(context.Context, string, string, []string, time.Time) (int, error) {
	return 0, nil
}
