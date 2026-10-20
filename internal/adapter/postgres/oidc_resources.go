package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"go.airlance.org/auth/internal/adapter/postgres/sqlc"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/oidc"
)

var (
	_ port.OIDCResourceRepository = (*oidcResources)(nil)
	_ port.OIDCAppRepository      = (*oidcApps)(nil)
)

// ---- resources

type oidcResources struct{ q *sqlc.Queries }

func resourceFromRow(r sqlc.OidcResource) *oidc.Resource {
	return &oidc.Resource{
		ID: r.ID, Name: r.Name, Status: r.Status, URI: r.Uri, Audience: r.Audience, Scopes: r.Scopes,
		PolicyVersion: int(r.PolicyVersion), CreatedAt: goTime(r.CreatedAt), UpdatedAt: goTime(r.UpdatedAt),
	}
}

func (r *oidcResources) Create(ctx context.Context, res *oidc.Resource) error {
	err := r.q.CreateOIDCResource(ctx, sqlc.CreateOIDCResourceParams{
		ID: res.ID, Name: res.Name, Status: res.Status, Uri: res.URI, Audience: res.Audience, Scopes: res.Scopes,
		PolicyVersion: int32(res.PolicyVersion), CreatedAt: dbTime(res.CreatedAt), UpdatedAt: dbTime(res.UpdatedAt),
	})

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
		return port.ErrResourceExists
	}

	if err != nil {
		return fmt.Errorf("create resource: %w", err)
	}

	return nil
}

func (r *oidcResources) Get(ctx context.Context, id string) (*oidc.Resource, error) {
	row, err := r.q.GetOIDCResource(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("get resource: %w", err)
	}

	return resourceFromRow(row), nil
}

func (r *oidcResources) GetForUpdate(ctx context.Context, id string) (*oidc.Resource, error) {
	row, err := r.q.GetOIDCResourceForUpdate(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("lock resource: %w", err)
	}

	return resourceFromRow(row), nil
}

func (r *oidcResources) ByURIsForShare(ctx context.Context, uris []string) ([]*oidc.Resource, error) {
	if len(uris) == 0 {
		return nil, nil
	}

	rows, err := r.q.ListOIDCResourcesByURIForShare(ctx, uris)
	if err != nil {
		return nil, fmt.Errorf("lock resources: %w", err)
	}

	out := make([]*oidc.Resource, 0, len(rows))
	for _, row := range rows {
		out = append(out, resourceFromRow(row))
	}

	return out, nil
}

func (r *oidcResources) ByIDsForShare(ctx context.Context, ids []string) ([]*oidc.Resource, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	rows, err := r.q.ListOIDCResourcesByIDForShare(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("lock resources: %w", err)
	}

	out := make([]*oidc.Resource, 0, len(rows))
	for _, row := range rows {
		out = append(out, resourceFromRow(row))
	}

	return out, nil
}

func (r *oidcResources) List(ctx context.Context) ([]*oidc.Resource, error) {
	rows, err := r.q.ListOIDCResources(ctx)
	if err != nil {
		return nil, fmt.Errorf("list resources: %w", err)
	}

	out := make([]*oidc.Resource, 0, len(rows))
	for _, row := range rows {
		out = append(out, resourceFromRow(row))
	}

	return out, nil
}

func (r *oidcResources) SetStatus(ctx context.Context, id, status string, now time.Time) error {
	n, err := r.q.SetOIDCResourceStatus(ctx, sqlc.SetOIDCResourceStatusParams{ID: id, Status: status, UpdatedAt: dbTime(now)})
	if err != nil {
		return fmt.Errorf("set resource status: %w", err)
	}

	if n == 0 {
		return port.ErrNotFound
	}

	return nil
}

func (r *oidcResources) SetScopes(ctx context.Context, id string, scopes []string, now time.Time) error {
	n, err := r.q.SetOIDCResourceScopes(ctx, sqlc.SetOIDCResourceScopesParams{ID: id, Scopes: scopes, UpdatedAt: dbTime(now)})
	if err != nil {
		return fmt.Errorf("set resource scopes: %w", err)
	}

	if n == 0 {
		return port.ErrNotFound
	}

	return nil
}

func (r *oidcResources) AudienceTaken(ctx context.Context, audience string) (bool, error) {
	taken, err := r.q.OIDCAudienceTaken(ctx, audience)
	if err != nil {
		return false, fmt.Errorf("check audience: %w", err)
	}

	return taken, nil
}

func (r *oidcResources) ClientScopes(ctx context.Context, clientID string, resourceIDs []string) (map[string][]string, error) {
	out := make(map[string][]string, len(resourceIDs))
	if len(resourceIDs) == 0 {
		return out, nil
	}

	rows, err := r.q.ListOIDCClientResourcesOf(ctx, sqlc.ListOIDCClientResourcesOfParams{ClientID: clientID, ResourceIds: resourceIDs})
	if err != nil {
		return nil, fmt.Errorf("list client resources: %w", err)
	}

	for _, row := range rows {
		out[row.ResourceID] = row.Scopes
	}

	return out, nil
}

func clientResources(rows []sqlc.OidcClientResource) []oidc.ClientResource {
	out := make([]oidc.ClientResource, 0, len(rows))
	for _, row := range rows {
		out = append(out, oidc.ClientResource{ClientID: row.ClientID, ResourceID: row.ResourceID, Scopes: row.Scopes})
	}

	return out
}

func (r *oidcResources) ClientResources(ctx context.Context, clientID string) ([]oidc.ClientResource, error) {
	rows, err := r.q.ListOIDCClientResources(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("list client resources: %w", err)
	}

	return clientResources(rows), nil
}

func (r *oidcResources) ResourceClients(ctx context.Context, resourceID string) ([]oidc.ClientResource, error) {
	rows, err := r.q.ListOIDCResourceClients(ctx, resourceID)
	if err != nil {
		return nil, fmt.Errorf("list resource clients: %w", err)
	}

	return clientResources(rows), nil
}

func (r *oidcResources) SetClientScopes(ctx context.Context, clientID, resourceID string, scopes []string, now time.Time) ([]string, error) {
	previous, err := r.previousClientScopes(ctx, clientID, resourceID)
	if err != nil {
		return nil, err
	}

	err = r.q.UpsertOIDCClientResource(ctx, sqlc.UpsertOIDCClientResourceParams{ClientID: clientID, ResourceID: resourceID, Scopes: scopes, CreatedAt: dbTime(now)})
	if err != nil {
		return nil, fmt.Errorf("allow client resource: %w", err)
	}

	return previous, nil
}

func (r *oidcResources) DeleteClientScopes(ctx context.Context, clientID, resourceID string) ([]string, error) {
	previous, err := r.previousClientScopes(ctx, clientID, resourceID)
	if err != nil {
		return nil, err
	}

	if _, err := r.q.DeleteOIDCClientResource(ctx, sqlc.DeleteOIDCClientResourceParams{ClientID: clientID, ResourceID: resourceID}); err != nil {
		return nil, fmt.Errorf("deny client resource: %w", err)
	}

	return previous, nil
}

func (r *oidcResources) previousClientScopes(ctx context.Context, clientID, resourceID string) ([]string, error) {
	row, err := r.q.GetOIDCClientResourceForUpdate(ctx, sqlc.GetOIDCClientResourceForUpdateParams{ClientID: clientID, ResourceID: resourceID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("lock client resource: %w", err)
	}

	return row.Scopes, nil
}

// ---- the resources of requests, codes and grants

func toResourceScopes(resourceID string, scopes []string, version int32) oidc.ResourceScopes {
	return oidc.ResourceScopes{ResourceID: resourceID, PolicyVersion: int(version), Scopes: scopes}
}

func (r *oidcRequests) createResources(ctx context.Context, hash []byte, list []oidc.ResourceScopes) error {
	for _, rs := range list {
		if err := r.q.CreateOIDCRequestResource(ctx, sqlc.CreateOIDCRequestResourceParams{
			RequestHash: hash, ResourceID: rs.ResourceID, Scopes: rs.Scopes, PolicyVersion: int32(rs.PolicyVersion),
		}); err != nil {
			return fmt.Errorf("store request resource: %w", err)
		}
	}

	return nil
}

func (r *oidcRequests) loadResources(ctx context.Context, hash []byte) ([]oidc.ResourceScopes, error) {
	rows, err := r.q.ListOIDCRequestResources(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("load request resources: %w", err)
	}

	out := make([]oidc.ResourceScopes, 0, len(rows))
	for _, row := range rows {
		out = append(out, toResourceScopes(row.ResourceID, row.Scopes, row.PolicyVersion))
	}

	return out, nil
}

func (r *oidcCodes) createResources(ctx context.Context, hash []byte, list []oidc.ResourceScopes) error {
	for _, rs := range list {
		if err := r.q.CreateOIDCCodeResource(ctx, sqlc.CreateOIDCCodeResourceParams{
			CodeHash: hash, ResourceID: rs.ResourceID, Scopes: rs.Scopes, PolicyVersion: int32(rs.PolicyVersion),
		}); err != nil {
			return fmt.Errorf("store code resource: %w", err)
		}
	}

	return nil
}

func (r *oidcCodes) loadResources(ctx context.Context, hash []byte) ([]oidc.ResourceScopes, error) {
	rows, err := r.q.ListOIDCCodeResources(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("load code resources: %w", err)
	}

	out := make([]oidc.ResourceScopes, 0, len(rows))
	for _, row := range rows {
		out = append(out, toResourceScopes(row.ResourceID, row.Scopes, row.PolicyVersion))
	}

	return out, nil
}

func createGrantResources(ctx context.Context, q *sqlc.Queries, grant uuid.UUID, list []oidc.ResourceScopes) error {
	for _, rs := range list {
		if err := q.CreateOIDCGrantResource(ctx, sqlc.CreateOIDCGrantResourceParams{
			GrantID: grant, ResourceID: rs.ResourceID, Scopes: rs.Scopes, PolicyVersion: int32(rs.PolicyVersion),
		}); err != nil {
			return fmt.Errorf("store grant resource: %w", err)
		}
	}

	return nil
}

func loadGrantResources(ctx context.Context, q *sqlc.Queries, grant uuid.UUID) ([]oidc.ResourceScopes, error) {
	rows, err := q.ListOIDCGrantResources(ctx, grant)
	if err != nil {
		return nil, fmt.Errorf("load grant resources: %w", err)
	}

	out := make([]oidc.ResourceScopes, 0, len(rows))
	for _, row := range rows {
		out = append(out, toResourceScopes(row.ResourceID, row.Scopes, row.PolicyVersion))
	}

	return out, nil
}

// ---- what users connected

type oidcApps struct{ q *sqlc.Queries }

func (r *oidcApps) LiveGrantsOfUser(ctx context.Context, userID identity.UserID, now time.Time) ([]port.AppGrant, error) {
	user, err := userUUID(userID)
	if err != nil {
		return nil, fmt.Errorf("list apps: %w", err)
	}

	rows, err := r.q.ListLiveOIDCGrantsOfUser(ctx, sqlc.ListLiveOIDCGrantsOfUserParams{UserID: user, Now: dbTime(now)})
	if err != nil {
		return nil, fmt.Errorf("list apps: %w", err)
	}

	out := make([]port.AppGrant, 0, len(rows))
	ids := make([]uuid.UUID, 0, len(rows))

	index := make(map[uuid.UUID]int, len(rows))
	for _, row := range rows {
		index[row.ID] = len(out)
		ids = append(ids, row.ID)
		out = append(out, port.AppGrant{
			ID: row.ID.String(), ClientID: row.ClientID, ClientName: row.ClientName, Scopes: row.Scopes, Resources: []port.AppResource{},
			CreatedAt: goTime(row.CreatedAt), LastUsedAt: goTime(row.LastUsedAt), ExpiresAt: goTime(row.ExpiresAt),
		})
	}

	if len(ids) == 0 {
		return out, nil
	}

	held, err := r.q.ListOIDCGrantResourcesOfGrants(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("list app resources: %w", err)
	}

	for _, h := range held {
		i := index[h.GrantID]
		out[i].Resources = append(out[i].Resources, port.AppResource{ID: h.ResourceID, Name: h.ResourceName, Scopes: h.Scopes})
	}

	return out, nil
}

// endGrant ends one grant that is already locked, with its refresh tokens, after queueing the notice of its client.
func endGrant(ctx context.Context, q *sqlc.Queries, grant uuid.UUID, now time.Time) error {
	if err := q.QueueOIDCLogoutOfGrant(ctx, sqlc.QueueOIDCLogoutOfGrantParams{Now: dbTime(now), ExpiresAt: dbTime(now.Add(oidc.LogoutNoticeTTL)), GrantID: grant}); err != nil {
		return fmt.Errorf("queue logout notice: %w", err)
	}

	t := dbTimePtr(now)
	if err := q.RevokeOIDCGrant(ctx, sqlc.RevokeOIDCGrantParams{ID: grant, RevokedAt: t}); err != nil {
		return fmt.Errorf("revoke grant: %w", err)
	}

	if err := q.RevokeOIDCGrantRefresh(ctx, sqlc.RevokeOIDCGrantRefreshParams{GrantID: grant, RevokedAt: t}); err != nil {
		return fmt.Errorf("revoke grant refresh tokens: %w", err)
	}

	return nil
}

func (r *oidcApps) RevokeOwned(ctx context.Context, userID identity.UserID, grantID string, now time.Time) (bool, string, error) {
	id, err := toUUID(grantID)
	if err != nil {
		return false, "", nil // not a grant id: nothing of the user's
	}

	user, err := userUUID(userID)
	if err != nil {
		return false, "", fmt.Errorf("revoke app: %w", err)
	}
	// The probe only finds the locks; whose grant it is, and whether it is live, is read again under them.
	probe, err := r.q.GetOIDCGrant(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && probe.UserID != user) {
		return false, "", nil
	}

	if err != nil {
		return false, "", fmt.Errorf("revoke app: %w", err)
	}

	locked, err := lockGrant(ctx, r.q, id)
	if errors.Is(err, port.ErrNotFound) {
		return false, "", nil
	}

	if err != nil {
		return false, "", err
	}

	if locked.UserID != user || locked.RevokedAt != nil {
		return false, "", nil
	}

	if err := endGrant(ctx, r.q, id, now); err != nil {
		return false, "", err
	}

	return true, locked.ClientID, nil
}

func (r *oidcApps) RevokeOwnedOfClient(ctx context.Context, userID identity.UserID, clientID string, now time.Time) (int, error) {
	user, err := userUUID(userID)
	if err != nil {
		return 0, fmt.Errorf("revoke apps: %w", err)
	}

	ids, err := r.q.ListLiveOIDCGrantIDsOfUserClient(ctx, sqlc.ListLiveOIDCGrantIDsOfUserClientParams{UserID: user, ClientID: clientID})
	if err != nil {
		return 0, fmt.Errorf("revoke apps: %w", err)
	}

	ended := 0

	for _, id := range ids {
		ok, _, err := r.RevokeOwned(ctx, userID, id.String(), now)
		if err != nil {
			return 0, err
		}

		if ok {
			ended++
		}
	}

	return ended, nil
}

func (r *oidcApps) RevokeOfResource(ctx context.Context, resourceID, clientID string, scopes []string, now time.Time) (int, error) {
	var client pgtype.Text
	if clientID != "" {
		client = pgtype.Text{String: clientID, Valid: true}
	}

	rows, err := r.q.ListLiveOIDCGrantsOfResource(ctx, sqlc.ListLiveOIDCGrantsOfResourceParams{ResourceID: resourceID, ClientID: client, Scopes: scopes})
	if err != nil {
		return 0, fmt.Errorf("list grants of resource: %w", err)
	}

	ended := 0

	for _, row := range rows {
		// The user is share-locked and then the grant, like every issuer does, and what was listed is checked again.
		locked, err := lockGrant(ctx, r.q, row.ID)
		if errors.Is(err, port.ErrNotFound) {
			continue
		}

		if err != nil {
			return 0, err
		}

		if locked.RevokedAt != nil {
			continue
		}

		if err := endGrant(ctx, r.q, row.ID, now); err != nil {
			return 0, err
		}

		ended++
	}

	return ended, nil
}

func (r *oidcResources) RotateSecret(ctx context.Context, resourceID, secretID string, secret oidc.SecretHash, now time.Time, overlap time.Duration) error {
	if _, err := r.q.GetOIDCResource(ctx, resourceID); errors.Is(err, pgx.ErrNoRows) {
		return port.ErrNotFound
	} else if err != nil {
		return fmt.Errorf("rotate resource secret: %w", err)
	}

	id, err := toUUID(secretID)
	if err != nil {
		return fmt.Errorf("resource secret: %w", err)
	}

	t, end := dbTime(now), dbTime(now.Add(overlap))
	if err := r.q.RetireOIDCResourceSecrets(ctx, sqlc.RetireOIDCResourceSecretsParams{ResourceID: resourceID, RevokedAt: &t}); err != nil {
		return fmt.Errorf("rotate resource secret: %w", err)
	}

	if err := r.q.EndOIDCResourceSecretsAt(ctx, sqlc.EndOIDCResourceSecretsAtParams{ResourceID: resourceID, ExpiresAt: &end}); err != nil {
		return fmt.Errorf("rotate resource secret: %w", err)
	}

	err = r.q.InsertOIDCResourceSecret(ctx, sqlc.InsertOIDCResourceSecretParams{
		ID: id, ResourceID: resourceID, SecretHash: secret.Bytes(), CreatedAt: t,
	})

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
		return port.ErrOIDCSecretCollision
	}

	if err != nil {
		return fmt.Errorf("store resource secret: %w", err)
	}

	return nil
}

func (r *oidcResources) SecretValid(ctx context.Context, resourceID string, secret oidc.SecretHash, now time.Time) (bool, error) {
	ok, err := r.q.OIDCResourceSecretValid(ctx, sqlc.OIDCResourceSecretValidParams{ResourceID: resourceID, SecretHash: secret.Bytes(), ExpiresAt: ptr(dbTime(now))})
	if err != nil {
		return false, fmt.Errorf("check resource secret: %w", err)
	}

	return ok, nil
}
