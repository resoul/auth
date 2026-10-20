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
	_ port.OIDCClientRepository  = (*oidcClients)(nil)
	_ port.OIDCRequestRepository = (*oidcRequests)(nil)
	_ port.OIDCSessionRepository = (*oidcSessions)(nil)
	_ port.OIDCGrantRepository   = (*oidcGrants)(nil)
	_ port.OIDCCodeRepository    = (*oidcCodes)(nil)
	_ port.OIDCRefreshRepository = (*oidcRefresh)(nil)
	_ port.OIDCLogoutRepository  = (*oidcLogout)(nil)
)

func hashFrom(b []byte) (oidc.SecretHash, error) { return oidc.SecretHashFrom(b) }

// lockGrant takes the locks of a grant in the one order every statement uses: the user (shared, so any number of
// issuers run together and a revoke-all, which takes it exclusively, waits for them), then the grant. Whatever is
// read before the locks is only used to find them; the caller reads again after.
func lockGrant(ctx context.Context, q *sqlc.Queries, grantID uuid.UUID) (sqlc.OidcGrant, error) {
	probe, err := q.GetOIDCGrant(ctx, grantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return sqlc.OidcGrant{}, port.ErrNotFound
	}

	if err != nil {
		return sqlc.OidcGrant{}, fmt.Errorf("load grant: %w", err)
	}

	if _, err := q.LockUserShare(ctx, probe.UserID); errors.Is(err, pgx.ErrNoRows) {
		return sqlc.OidcGrant{}, port.ErrNotFound
	} else if err != nil {
		return sqlc.OidcGrant{}, fmt.Errorf("lock user: %w", err)
	}

	locked, err := q.GetOIDCGrantForUpdate(ctx, grantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return sqlc.OidcGrant{}, port.ErrNotFound
	}

	if err != nil {
		return sqlc.OidcGrant{}, fmt.Errorf("lock grant: %w", err)
	}

	return locked, nil
}

func grantFromRow(r sqlc.OidcGrant) (*oidc.Grant, error) {
	user, err := identity.ParseUserID(r.UserID.String())
	if err != nil {
		return nil, fmt.Errorf("stored grant user: %w", err)
	}

	return &oidc.Grant{
		ID: r.ID.String(), ClientID: r.ClientID, UserID: user, OPSessionID: r.OpSessionID.String(), Scopes: r.Scopes,
		PolicyVersion: int(r.PolicyVersion), CreatedAt: goTime(r.CreatedAt), LastUsedAt: goTime(r.LastUsedAt),
		ExpiresAt: goTime(r.ExpiresAt), RevokedAt: goTimePtr(r.RevokedAt),
	}, nil
}

// ---- clients

type oidcClients struct{ q *sqlc.Queries }

func clientFromRow(r sqlc.OidcClient) *oidc.Client {
	return &oidc.Client{
		ID: r.ID, Name: r.Name, Status: r.Status, RedirectURIs: r.RedirectUris, AllowedScopes: r.AllowedScopes, Trusted: r.Trusted,
		PolicyVersion: int(r.PolicyVersion), CreatedAt: goTime(r.CreatedAt), UpdatedAt: goTime(r.UpdatedAt),
		PostLogoutRedirectURIs: r.PostLogoutRedirectUris, BackchannelLogoutURI: deref(r.BackchannelLogoutUri), Kind: r.Kind,
	}
}

func deref(s pgtype.Text) string {
	if !s.Valid {
		return ""
	}

	return s.String
}

// text is a nullable text column: empty is NULL.
func text(s string) pgtype.Text { return pgtype.Text{String: s, Valid: s != ""} }

func (r *oidcClients) Create(ctx context.Context, c *oidc.Client, secretID string, secret oidc.SecretHash) error {
	err := r.q.CreateOIDCClient(ctx, sqlc.CreateOIDCClientParams{
		ID: c.ID, Name: c.Name, Status: c.Status, RedirectUris: nonNil(c.RedirectURIs), AllowedScopes: nonNil(c.AllowedScopes), Trusted: c.Trusted,
		PolicyVersion: int32(c.PolicyVersion), CreatedAt: dbTime(c.CreatedAt), UpdatedAt: dbTime(c.UpdatedAt),
		PostLogoutRedirectUris: nonNil(c.PostLogoutRedirectURIs), BackchannelLogoutUri: text(c.BackchannelLogoutURI), Kind: c.Kind,
	})

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation && pgErr.ConstraintName == "oidc_clients_pkey" {
		return port.ErrClientExists
	}

	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	return r.insertSecret(ctx, c.ID, secretID, secret, c.CreatedAt, nil)
}

func (r *oidcClients) insertSecret(ctx context.Context, clientID, secretID string, secret oidc.SecretHash, now time.Time, expires *time.Time) error {
	id, err := toUUID(secretID)
	if err != nil {
		return fmt.Errorf("client secret: %w", err)
	}

	err = r.q.InsertOIDCClientSecret(ctx, sqlc.InsertOIDCClientSecretParams{
		ID: id, ClientID: clientID, SecretHash: secret.Bytes(), CreatedAt: dbTime(now), ExpiresAt: expires,
	})

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
		return port.ErrOIDCSecretCollision
	}

	if err != nil {
		return fmt.Errorf("store client secret: %w", err)
	}

	return nil
}

func (r *oidcClients) Get(ctx context.Context, id string) (*oidc.Client, error) {
	row, err := r.q.GetOIDCClient(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("get client: %w", err)
	}

	return clientFromRow(row), nil
}

func (r *oidcClients) List(ctx context.Context) ([]*oidc.Client, error) {
	rows, err := r.q.ListOIDCClients(ctx)
	if err != nil {
		return nil, fmt.Errorf("list clients: %w", err)
	}

	out := make([]*oidc.Client, 0, len(rows))
	for _, row := range rows {
		out = append(out, clientFromRow(row))
	}

	return out, nil
}

func (r *oidcClients) SetStatus(ctx context.Context, id, status string, now time.Time) error {
	n, err := r.q.SetOIDCClientStatus(ctx, sqlc.SetOIDCClientStatusParams{ID: id, Status: status, UpdatedAt: dbTime(now)})
	if err != nil {
		return fmt.Errorf("set client status: %w", err)
	}

	if n == 0 {
		return port.ErrNotFound
	}

	return nil
}

func (r *oidcClients) RotateSecret(ctx context.Context, id, secretID string, secret oidc.SecretHash, now time.Time, overlap time.Duration) error {
	if _, err := r.q.GetOIDCClient(ctx, id); errors.Is(err, pgx.ErrNoRows) {
		return port.ErrNotFound
	} else if err != nil {
		return fmt.Errorf("rotate client secret: %w", err)
	}

	t := dbTime(now)
	end := dbTime(now.Add(overlap))

	if err := r.q.RetireOIDCClientSecrets(ctx, sqlc.RetireOIDCClientSecretsParams{ClientID: id, RevokedAt: &t}); err != nil {
		return fmt.Errorf("rotate client secret: %w", err)
	}

	if err := r.q.EndOIDCClientSecretsAt(ctx, sqlc.EndOIDCClientSecretsAtParams{ClientID: id, ExpiresAt: &end}); err != nil {
		return fmt.Errorf("rotate client secret: %w", err)
	}

	return r.insertSecret(ctx, id, secretID, secret, now, nil)
}

func (r *oidcClients) SecretValid(ctx context.Context, id string, secret oidc.SecretHash, now time.Time) (bool, error) {
	ok, err := r.q.OIDCClientSecretValid(ctx, sqlc.OIDCClientSecretValidParams{ClientID: id, SecretHash: secret.Bytes(), ExpiresAt: ptr(dbTime(now))})
	if err != nil {
		return false, fmt.Errorf("check client secret: %w", err)
	}

	return ok, nil
}

func ptr[T any](v T) *T { return &v }

// nonNil turns a nil list into an empty one: the column is NOT NULL, and an unset list is an empty one.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}

	return s
}

func (r *oidcClients) SetLogout(ctx context.Context, id string, postLogout []string, backchannel string, now time.Time) error {
	n, err := r.q.SetOIDCClientLogout(ctx, sqlc.SetOIDCClientLogoutParams{
		ID: id, PostLogoutRedirectUris: nonNil(postLogout), BackchannelLogoutUri: text(backchannel), UpdatedAt: dbTime(now),
	})
	if err != nil {
		return fmt.Errorf("set client logout: %w", err)
	}

	if n == 0 {
		return port.ErrNotFound
	}

	return nil
}

// ---- authorization requests

type oidcRequests struct{ q *sqlc.Queries }

func (r *oidcRequests) Create(ctx context.Context, a *oidc.AuthorizationRequest) error {
	var maxAge pgtype.Int4
	if a.MaxAge != nil {
		maxAge = pgtype.Int4{Int32: int32(*a.MaxAge), Valid: true}
	}

	err := r.q.CreateOIDCRequest(ctx, sqlc.CreateOIDCRequestParams{
		IDHash: a.ID.Bytes(), BindingHash: a.Binding.Bytes(), ClientID: a.ClientID, RedirectUri: a.RedirectURI, Scopes: a.Scopes,
		State: a.State, Nonce: a.Nonce, CodeChallenge: a.CodeChallenge, FreshLogin: a.FreshLogin, MaxAge: maxAge,
		CreatedAt: dbTime(a.CreatedAt), ExpiresAt: dbTime(a.ExpiresAt),
	})
	if err != nil {
		return fmt.Errorf("create authorization request: %w", err)
	}

	return r.createResources(ctx, a.ID.Bytes(), a.Resources)
}

func (r *oidcRequests) GetForUpdate(ctx context.Context, id oidc.SecretHash) (*oidc.AuthorizationRequest, error) {
	row, err := r.q.GetOIDCRequestForUpdate(ctx, id.Bytes())
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("get authorization request: %w", err)
	}

	idHash, err := hashFrom(row.IDHash)
	if err != nil {
		return nil, err
	}

	binding, err := hashFrom(row.BindingHash)
	if err != nil {
		return nil, err
	}

	out := &oidc.AuthorizationRequest{
		ID: idHash, Binding: binding, ClientID: row.ClientID, RedirectURI: row.RedirectUri, Scopes: row.Scopes, State: row.State,
		Nonce: row.Nonce, CodeChallenge: row.CodeChallenge, FreshLogin: row.FreshLogin,
		CreatedAt: goTime(row.CreatedAt), ExpiresAt: goTime(row.ExpiresAt), CompletedAt: goTimePtr(row.CompletedAt),
	}
	if row.MaxAge.Valid {
		v := int(row.MaxAge.Int32)
		out.MaxAge = &v
	}

	if out.Resources, err = r.loadResources(ctx, id.Bytes()); err != nil {
		return nil, err
	}

	return out, nil
}

func (r *oidcRequests) Complete(ctx context.Context, id oidc.SecretHash, now time.Time) error {
	n, err := r.q.CompleteOIDCRequest(ctx, sqlc.CompleteOIDCRequestParams{IDHash: id.Bytes(), CompletedAt: ptr(dbTime(now))})
	if err != nil {
		return fmt.Errorf("complete authorization request: %w", err)
	}

	if n == 0 {
		return port.ErrNotFound
	}

	return nil
}

// ---- OP sessions

type oidcSessions struct{ q *sqlc.Queries }

func opSessionFromRow(id uuid.UUID, user uuid.UUID, secret []byte, authTime time.Time, amr []string, created, seen, expires time.Time, revoked *time.Time, device *uuid.UUID) (*oidc.OPSession, error) {
	uid, err := identity.ParseUserID(user.String())
	if err != nil {
		return nil, fmt.Errorf("stored op session user: %w", err)
	}

	h, err := hashFrom(secret)
	if err != nil {
		return nil, err
	}

	out := &oidc.OPSession{
		ID: id.String(), UserID: uid, SecretHash: h, AuthTime: goTime(authTime), AMR: amr,
		CreatedAt: goTime(created), LastSeenAt: goTime(seen), ExpiresAt: goTime(expires), RevokedAt: goTimePtr(revoked),
	}
	if device != nil {
		out.DeviceSessionID = device.String()
	}

	return out, nil
}

func (r *oidcSessions) Create(ctx context.Context, s *oidc.OPSession) error {
	id, err := toUUID(s.ID)
	if err != nil {
		return fmt.Errorf("create op session: %w", err)
	}

	user, err := userUUID(s.UserID)
	if err != nil {
		return fmt.Errorf("create op session: %w", err)
	}

	var device *uuid.UUID

	if s.DeviceSessionID != "" {
		d, err := toUUID(s.DeviceSessionID)
		if err != nil {
			return fmt.Errorf("create op session: %w", err)
		}

		device = &d
	}

	err = r.q.CreateOIDCOPSession(ctx, sqlc.CreateOIDCOPSessionParams{
		ID: id, UserID: user, SecretHash: s.SecretHash.Bytes(), AuthTime: dbTime(s.AuthTime), Amr: s.AMR,
		CreatedAt: dbTime(s.CreatedAt), LastSeenAt: dbTime(s.LastSeenAt), ExpiresAt: dbTime(s.ExpiresAt), DeviceSessionID: device,
	})
	if err != nil {
		return fmt.Errorf("create op session: %w", err)
	}

	return nil
}

func (r *oidcSessions) GetBySecret(ctx context.Context, secret oidc.SecretHash) (*oidc.OPSession, error) {
	row, err := r.q.GetOIDCOPSessionBySecret(ctx, secret.Bytes())
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("get op session: %w", err)
	}

	return opSessionFromRow(row.ID, row.UserID, row.SecretHash, row.AuthTime, row.Amr, row.CreatedAt, row.LastSeenAt, row.ExpiresAt, row.RevokedAt, row.DeviceSessionID)
}

func (r *oidcSessions) Get(ctx context.Context, id string) (*oidc.OPSession, error) {
	u, err := toUUID(id)
	if err != nil {
		return nil, port.ErrNotFound
	}

	row, err := r.q.GetOIDCOPSession(ctx, u)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("get op session: %w", err)
	}

	return opSessionFromRow(row.ID, row.UserID, row.SecretHash, row.AuthTime, row.Amr, row.CreatedAt, row.LastSeenAt, row.ExpiresAt, row.RevokedAt, row.DeviceSessionID)
}

func (r *oidcSessions) Touch(ctx context.Context, id string, now time.Time) error {
	u, err := toUUID(id)
	if err != nil {
		return fmt.Errorf("touch op session: %w", err)
	}

	if err := r.q.TouchOIDCOPSession(ctx, sqlc.TouchOIDCOPSessionParams{ID: u, LastSeenAt: dbTime(now)}); err != nil {
		return fmt.Errorf("touch op session: %w", err)
	}

	return nil
}

func (r *oidcSessions) RevokeAllForUser(ctx context.Context, userID identity.UserID, now time.Time) error {
	user, err := userUUID(userID)
	if err != nil {
		return fmt.Errorf("revoke op sessions: %w", err)
	}

	if _, err := lockUser(ctx, r.q, userID); err != nil {
		return fmt.Errorf("revoke op sessions: %w", err)
	}

	t := dbTimePtr(now)
	// The notices are queued from the live grants, so before the grants are revoked.
	if err := r.q.QueueOIDCLogoutOfUser(ctx, sqlc.QueueOIDCLogoutOfUserParams{Now: dbTime(now), ExpiresAt: dbTime(now.Add(oidc.LogoutNoticeTTL)), UserID: user}); err != nil {
		return fmt.Errorf("queue logout notices: %w", err)
	}

	if err := r.q.RevokeOIDCOPSessionsOfUser(ctx, sqlc.RevokeOIDCOPSessionsOfUserParams{UserID: user, RevokedAt: t}); err != nil {
		return fmt.Errorf("revoke op sessions: %w", err)
	}

	if err := r.q.RevokeOIDCGrantsOfUser(ctx, sqlc.RevokeOIDCGrantsOfUserParams{UserID: user, RevokedAt: t}); err != nil {
		return fmt.Errorf("revoke grants: %w", err)
	}

	if err := r.q.RevokeOIDCRefreshOfUser(ctx, sqlc.RevokeOIDCRefreshOfUserParams{UserID: user, RevokedAt: t}); err != nil {
		return fmt.Errorf("revoke refresh tokens: %w", err)
	}

	return nil
}

func (r *oidcSessions) RevokeOthersForUser(ctx context.Context, userID identity.UserID, keep string, now time.Time) error {
	user, err := userUUID(userID)
	if err != nil {
		return fmt.Errorf("revoke other op sessions: %w", err)
	}

	if _, err := lockUser(ctx, r.q, userID); err != nil {
		return fmt.Errorf("revoke other op sessions: %w", err)
	}

	var kept *uuid.UUID // NULL keeps nothing
	if id, err := toUUID(keep); err == nil {
		kept = &id
	}

	t := dbTimePtr(now)
	// The notices are queued from the live grants, so before the grants are revoked.
	if err := r.q.QueueOIDCLogoutOfUserExcept(ctx, sqlc.QueueOIDCLogoutOfUserExceptParams{Now: dbTime(now), ExpiresAt: dbTime(now.Add(oidc.LogoutNoticeTTL)), UserID: user, Keep: kept}); err != nil {
		return fmt.Errorf("queue logout notices: %w", err)
	}

	if err := r.q.RevokeOIDCRefreshOfUserExcept(ctx, sqlc.RevokeOIDCRefreshOfUserExceptParams{RevokedAt: t, UserID: user, Keep: kept}); err != nil {
		return fmt.Errorf("revoke refresh tokens: %w", err)
	}

	if err := r.q.RevokeOIDCGrantsOfUserExcept(ctx, sqlc.RevokeOIDCGrantsOfUserExceptParams{RevokedAt: t, UserID: user, Keep: kept}); err != nil {
		return fmt.Errorf("revoke grants: %w", err)
	}

	if err := r.q.RevokeOIDCOPSessionsOfUserExcept(ctx, sqlc.RevokeOIDCOPSessionsOfUserExceptParams{RevokedAt: t, UserID: user, Keep: kept}); err != nil {
		return fmt.Errorf("revoke op sessions: %w", err)
	}

	return nil
}

func (r *oidcSessions) End(ctx context.Context, id string, now time.Time) error {
	session, err := toUUID(id)
	if err != nil {
		return nil // not a session id: nothing to end
	}

	owner, err := r.q.GetOIDCOPSessionUserID(ctx, session)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("end op session: %w", err)
	}
	// The user is locked exclusively before the grants are listed: an issuer that holds the user (shared) and is opening a
	// grant on this session finishes first, and its grant is seen and ended.
	uid, err := identity.ParseUserID(owner.String())
	if err != nil {
		return fmt.Errorf("end op session: %w", err)
	}

	if _, err := lockUser(ctx, r.q, uid); err != nil {
		return fmt.Errorf("end op session: %w", err)
	}

	t := dbTimePtr(now)
	if err := r.q.QueueOIDCLogoutOfSession(ctx, sqlc.QueueOIDCLogoutOfSessionParams{Now: dbTime(now), ExpiresAt: dbTime(now.Add(oidc.LogoutNoticeTTL)), OpSessionID: session}); err != nil {
		return fmt.Errorf("queue logout notices: %w", err)
	}

	if err := r.q.EndOIDCOPSession(ctx, sqlc.EndOIDCOPSessionParams{ID: session, RevokedAt: t}); err != nil {
		return fmt.Errorf("end op session: %w", err)
	}

	if err := r.q.RevokeOIDCGrantsOfSession(ctx, sqlc.RevokeOIDCGrantsOfSessionParams{OpSessionID: session, RevokedAt: t}); err != nil {
		return fmt.Errorf("revoke grants: %w", err)
	}

	if err := r.q.RevokeOIDCRefreshOfSession(ctx, sqlc.RevokeOIDCRefreshOfSessionParams{OpSessionID: session, RevokedAt: t}); err != nil {
		return fmt.Errorf("revoke refresh tokens: %w", err)
	}

	return nil
}

// ---- grants

type oidcGrants struct{ q *sqlc.Queries }

func (r *oidcGrants) FindLive(ctx context.Context, clientID, opSessionID string) (*oidc.Grant, error) {
	op, err := toUUID(opSessionID)
	if err != nil {
		return nil, port.ErrNotFound
	}

	row, err := r.q.FindLiveOIDCGrant(ctx, sqlc.FindLiveOIDCGrantParams{ClientID: clientID, OpSessionID: op})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("find grant: %w", err)
	}

	return r.withResources(ctx, sqlc.OidcGrant(row))
}

// withResources builds the grant of a row together with what it holds of each resource.
func (r *oidcGrants) withResources(ctx context.Context, row sqlc.OidcGrant) (*oidc.Grant, error) {
	g, err := grantFromRow(row)
	if err != nil {
		return nil, err
	}

	if g.Resources, err = loadGrantResources(ctx, r.q, row.ID); err != nil {
		return nil, err
	}

	return g, nil
}

func (r *oidcGrants) Create(ctx context.Context, g *oidc.Grant) error {
	id, err := toUUID(g.ID)
	if err != nil {
		return fmt.Errorf("create grant: %w", err)
	}

	user, err := userUUID(g.UserID)
	if err != nil {
		return fmt.Errorf("create grant: %w", err)
	}

	op, err := toUUID(g.OPSessionID)
	if err != nil {
		return fmt.Errorf("create grant: %w", err)
	}

	err = r.q.CreateOIDCGrant(ctx, sqlc.CreateOIDCGrantParams{
		ID: id, ClientID: g.ClientID, UserID: user, OpSessionID: op, Scopes: g.Scopes, PolicyVersion: int32(g.PolicyVersion),
		CreatedAt: dbTime(g.CreatedAt), LastUsedAt: dbTime(g.LastUsedAt), ExpiresAt: dbTime(g.ExpiresAt),
	})
	if err != nil {
		return fmt.Errorf("create grant: %w", err)
	}

	return createGrantResources(ctx, r.q, id, g.Resources)
}

func (r *oidcGrants) Get(ctx context.Context, id string) (*oidc.Grant, error) {
	u, err := toUUID(id)
	if err != nil {
		return nil, port.ErrNotFound
	}

	row, err := r.q.GetOIDCGrant(ctx, u)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("get grant: %w", err)
	}

	return r.withResources(ctx, row)
}

func (r *oidcGrants) Touch(ctx context.Context, id string, now time.Time) error {
	u, err := toUUID(id)
	if err != nil {
		return fmt.Errorf("touch grant: %w", err)
	}

	if err := r.q.TouchOIDCGrant(ctx, sqlc.TouchOIDCGrantParams{ID: u, LastUsedAt: dbTime(now)}); err != nil {
		return fmt.Errorf("touch grant: %w", err)
	}

	return nil
}

func (r *oidcGrants) Revoke(ctx context.Context, id string, now time.Time) error {
	u, err := toUUID(id)
	if err != nil {
		return nil // not a grant id: nothing to end
	}

	t := dbTimePtr(now)
	if err := r.q.RevokeOIDCGrant(ctx, sqlc.RevokeOIDCGrantParams{ID: u, RevokedAt: t}); err != nil {
		return fmt.Errorf("revoke grant: %w", err)
	}

	if err := r.q.RevokeOIDCGrantRefresh(ctx, sqlc.RevokeOIDCGrantRefreshParams{GrantID: u, RevokedAt: t}); err != nil {
		return fmt.Errorf("revoke grant refresh tokens: %w", err)
	}

	return nil
}

func (r *oidcGrants) RevokeAllForClient(ctx context.Context, clientID string, now time.Time) error {
	t := dbTimePtr(now)
	if err := r.q.RevokeOIDCGrantsOfClient(ctx, sqlc.RevokeOIDCGrantsOfClientParams{ClientID: clientID, RevokedAt: t}); err != nil {
		return fmt.Errorf("revoke grants of client: %w", err)
	}

	if err := r.q.RevokeOIDCRefreshOfClient(ctx, sqlc.RevokeOIDCRefreshOfClientParams{ClientID: clientID, RevokedAt: t}); err != nil {
		return fmt.Errorf("revoke refresh tokens of client: %w", err)
	}

	return nil
}

// ---- codes

type oidcCodes struct{ q *sqlc.Queries }

func (r *oidcCodes) Create(ctx context.Context, c *oidc.AuthorizationCode) error {
	grant, err := toUUID(c.GrantID)
	if err != nil {
		return fmt.Errorf("create code: %w", err)
	}

	err = r.q.CreateOIDCCode(ctx, sqlc.CreateOIDCCodeParams{
		CodeHash: c.Hash.Bytes(), GrantID: grant, RedirectUri: c.RedirectURI, CodeChallenge: c.CodeChallenge, Nonce: c.Nonce,
		Scopes: c.Scopes, AuthTime: dbTime(c.AuthTime), Amr: c.AMR, CreatedAt: dbTime(c.CreatedAt), ExpiresAt: dbTime(c.ExpiresAt),
	})

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
		return port.ErrOIDCSecretCollision
	}

	if err != nil {
		return fmt.Errorf("create code: %w", err)
	}

	return r.createResources(ctx, c.Hash.Bytes(), c.Resources)
}

func (r *oidcCodes) GetByHashForUpdate(ctx context.Context, hash oidc.SecretHash) (*oidc.AuthorizationCode, *oidc.Grant, error) {
	grantID, err := r.q.GetOIDCCodeGrantID(ctx, hash.Bytes())
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, port.ErrNotFound
	}

	if err != nil {
		return nil, nil, fmt.Errorf("get code: %w", err)
	}

	grantRow, err := lockGrant(ctx, r.q, grantID)
	if err != nil {
		return nil, nil, err
	}

	row, err := r.q.GetOIDCCodeForUpdate(ctx, hash.Bytes())
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, port.ErrNotFound
	}

	if err != nil {
		return nil, nil, fmt.Errorf("lock code: %w", err)
	}

	grant, err := (&oidcGrants{q: r.q}).withResources(ctx, grantRow)
	if err != nil {
		return nil, nil, err
	}

	resources, err := r.loadResources(ctx, hash.Bytes())
	if err != nil {
		return nil, nil, err
	}

	return &oidc.AuthorizationCode{
		Hash: hash, GrantID: row.GrantID.String(), RedirectURI: row.RedirectUri, CodeChallenge: row.CodeChallenge, Nonce: row.Nonce,
		Scopes: row.Scopes, Resources: resources, AuthTime: goTime(row.AuthTime), AMR: row.Amr, CreatedAt: goTime(row.CreatedAt),
		ExpiresAt: goTime(row.ExpiresAt), ConsumedAt: goTimePtr(row.ConsumedAt),
	}, grant, nil
}

func (r *oidcCodes) Consume(ctx context.Context, c *oidc.AuthorizationCode) error {
	n, err := r.q.ConsumeOIDCCode(ctx, sqlc.ConsumeOIDCCodeParams{CodeHash: c.Hash.Bytes(), ConsumedAt: dbTimePtr(c.ConsumedAt)})
	if err != nil {
		return fmt.Errorf("consume code: %w", err)
	}

	if n != 1 {
		return fmt.Errorf("consume code: the code was consumed by another transaction")
	}

	return nil
}

// ---- refresh tokens

type oidcRefresh struct{ q *sqlc.Queries }

func (r *oidcRefresh) Create(ctx context.Context, t *oidc.RefreshToken) error {
	id, err := toUUID(t.ID)
	if err != nil {
		return fmt.Errorf("create refresh token: %w", err)
	}

	grant, err := toUUID(t.GrantID)
	if err != nil {
		return fmt.Errorf("create refresh token: %w", err)
	}

	var parent *uuid.UUID

	if t.ParentID != "" {
		p, err := toUUID(t.ParentID)
		if err != nil {
			return fmt.Errorf("create refresh token: %w", err)
		}

		parent = &p
	}

	err = r.q.CreateOIDCRefresh(ctx, sqlc.CreateOIDCRefreshParams{
		ID: id, GrantID: grant, TokenHash: t.Hash.Bytes(), ParentID: parent, CreatedAt: dbTime(t.CreatedAt), ExpiresAt: dbTime(t.ExpiresAt),
	})

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
		if pgErr.ConstraintName == "oidc_refresh_one_child" {
			return port.ErrRefreshConflict
		}

		return port.ErrOIDCSecretCollision
	}

	if err != nil {
		return fmt.Errorf("create refresh token: %w", err)
	}

	return nil
}

func (r *oidcRefresh) GetByHashForUpdate(ctx context.Context, hash oidc.SecretHash) (*oidc.RefreshToken, *oidc.Grant, error) {
	grantID, err := r.q.GetOIDCRefreshGrantID(ctx, hash.Bytes())
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, port.ErrNotFound
	}

	if err != nil {
		return nil, nil, fmt.Errorf("get refresh token: %w", err)
	}

	grantRow, err := lockGrant(ctx, r.q, grantID)
	if err != nil {
		return nil, nil, err
	}

	row, err := r.q.GetOIDCRefreshForUpdate(ctx, hash.Bytes())
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, port.ErrNotFound
	}

	if err != nil {
		return nil, nil, fmt.Errorf("lock refresh token: %w", err)
	}

	grant, err := (&oidcGrants{q: r.q}).withResources(ctx, grantRow)
	if err != nil {
		return nil, nil, err
	}

	token := &oidc.RefreshToken{
		ID: row.ID.String(), GrantID: row.GrantID.String(), Hash: hash, CreatedAt: goTime(row.CreatedAt),
		ExpiresAt: goTime(row.ExpiresAt), UsedAt: goTimePtr(row.UsedAt), RevokedAt: goTimePtr(row.RevokedAt),
	}
	if row.ParentID != nil {
		token.ParentID = row.ParentID.String()
	}

	return token, grant, nil
}

func (r *oidcRefresh) MarkUsed(ctx context.Context, t *oidc.RefreshToken) error {
	id, err := toUUID(t.ID)
	if err != nil {
		return fmt.Errorf("mark refresh token used: %w", err)
	}

	n, err := r.q.MarkOIDCRefreshUsed(ctx, sqlc.MarkOIDCRefreshUsedParams{ID: id, UsedAt: dbTimePtr(t.UsedAt)})
	if err != nil {
		return fmt.Errorf("mark refresh token used: %w", err)
	}

	if n != 1 {
		return fmt.Errorf("mark refresh token used: the token was used by another transaction")
	}

	return nil
}

// ---- logout notices

type oidcLogout struct{ q *sqlc.Queries }

func (r *oidcLogout) Claim(ctx context.Context, now, leaseUntil time.Time) (*port.ClaimedLogout, error) {
	row, err := r.q.ClaimOIDCLogout(ctx, sqlc.ClaimOIDCLogoutParams{Now: dbTime(now), LeaseUntil: dbTime(leaseUntil)})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, port.ErrNotFound
	}

	if err != nil {
		return nil, fmt.Errorf("claim logout notice: %w", err)
	}

	user, err := identity.ParseUserID(row.UserID.String())
	if err != nil {
		return nil, fmt.Errorf("stored notice user: %w", err)
	}

	uri := row.BackchannelUri
	if row.ClientStatus != oidc.ClientActive {
		uri = "" // a disabled client is not told anything
	}

	return &port.ClaimedLogout{
		ID: row.ID.String(), ClientID: row.ClientID, BackchannelURI: uri, UserID: user, SessionID: row.OpSessionID.String(),
		Attempts: int(row.Attempts), CreatedAt: goTime(row.CreatedAt), ExpiresAt: goTime(row.ExpiresAt),
	}, nil
}

func (r *oidcLogout) Complete(ctx context.Context, id string) error {
	u, err := toUUID(id)
	if err != nil {
		return fmt.Errorf("complete logout notice: %w", err)
	}

	if _, err := r.q.CompleteOIDCLogout(ctx, u); err != nil {
		return fmt.Errorf("complete logout notice: %w", err)
	}

	return nil
}

func (r *oidcLogout) Retry(ctx context.Context, id string, availableAt time.Time, reason string) error {
	u, err := toUUID(id)
	if err != nil {
		return fmt.Errorf("retry logout notice: %w", err)
	}

	if _, err := r.q.RetryOIDCLogout(ctx, sqlc.RetryOIDCLogoutParams{ID: u, AvailableAt: dbTime(availableAt), LastError: pgtype.Text{String: reason, Valid: true}}); err != nil {
		return fmt.Errorf("retry logout notice: %w", err)
	}

	return nil
}

func (r *oidcLogout) Abandon(ctx context.Context, id string, reason string) error {
	u, err := toUUID(id)
	if err != nil {
		return fmt.Errorf("abandon logout notice: %w", err)
	}

	if _, err := r.q.AbandonOIDCLogout(ctx, sqlc.AbandonOIDCLogoutParams{ID: u, LastError: pgtype.Text{String: reason, Valid: true}}); err != nil {
		return fmt.Errorf("abandon logout notice: %w", err)
	}

	return nil
}

func (r *oidcLogout) Enqueue(ctx context.Context, id, clientID string, userID identity.UserID, sessionID string, now, expiresAt time.Time) error {
	nid, err := toUUID(id)
	if err != nil {
		return fmt.Errorf("enqueue logout notice: %w", err)
	}

	user, err := userUUID(userID)
	if err != nil {
		return fmt.Errorf("enqueue logout notice: %w", err)
	}

	sid, err := toUUID(sessionID)
	if err != nil {
		return fmt.Errorf("enqueue logout notice: %w", err)
	}

	err = r.q.EnqueueOIDCLogout(ctx, sqlc.EnqueueOIDCLogoutParams{
		ID: nid, ClientID: clientID, UserID: user, OpSessionID: sid, AvailableAt: dbTime(now), ExpiresAt: dbTime(expiresAt), CreatedAt: dbTime(now),
	})
	if err != nil {
		return fmt.Errorf("enqueue logout notice: %w", err)
	}

	return nil
}
