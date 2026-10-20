package oidc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.airlance.org/auth/internal/application/port"
	doidc "go.airlance.org/auth/internal/domain/oidc"
)

// Introspect is the token introspection endpoint (RFC 7662) for the APIs. An API checks the signature of a token itself;
// this is how it also learns, at the moment it asks, that the grant behind the token is still alive: the rights were
// not taken away, the person did not revoke the application, the sign-in did not end. An API that does not ask
// accepts a token until it expires.
//
// A service's token (client_credentials) is answered the same way, with the client as its subject.
//
// The caller is an API, not an application: it authenticates with the credentials of its resource, and it learns
// about tokens issued for that resource only. A token for another resource, a token of another kind, one that is
// expired, forged or ended all get the same answer, {"active": false}, so the endpoint tells an API nothing about
// tokens that are not its own.
type Introspect struct{ Deps }

// NewIntrospect checks the dependencies once, at assembly time.
func NewIntrospect(d Deps) (*Introspect, error) {
	if err := d.validate("introspect"); err != nil {
		return nil, err
	}

	return &Introspect{d}, nil
}

// IntrospectCommand is the input of Introspect.
type IntrospectCommand struct {
	ResourceID string
	Secret     string
	Token      string
}

// TokenInfo is what an API is told of a live token.
type TokenInfo struct {
	Scope     []string
	ClientID  string
	Subject   string
	Audience  string
	JTI       string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// IntrospectResult is the output of Introspect. A Failure is the refusal of the caller; otherwise a nil Token is
// {"active": false}.
type IntrospectResult struct {
	Token   *TokenInfo
	Failure *Failure
}

// Execute authenticates the API and says whether the token is live.
func (u *Introspect) Execute(ctx context.Context, cmd IntrospectCommand) (IntrospectResult, error) {
	now := u.Clock.Now()
	refused := IntrospectResult{Failure: fail(ErrInvalidClient, "The resource could not be authenticated.")}

	hash, err := u.Secrets.HashOIDCSecret(cmd.Secret)
	if errors.Is(err, port.ErrInvalidOIDCSecret) {
		return refused, nil
	}

	if err != nil {
		return IntrospectResult{}, fmt.Errorf("introspect: hash secret: %w", err)
	}

	var (
		result IntrospectResult
		asked  string
	)

	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		// The resource is read first and shared, as when a token is issued, so an answer is never given halfway through a
		// change of its rights.
		found, err := st.OIDCResources.ByIDsForShare(ctx, []string{cmd.ResourceID})
		if err != nil {
			return fmt.Errorf("load resource: %w", err)
		}

		if len(found) != 1 {
			result = refused
			return nil
		}

		res := found[0]
		asked = res.ID

		ok, err := st.OIDCResources.SecretValid(ctx, res.ID, hash, now)
		if err != nil {
			return err
		}

		if !ok || !res.Active() {
			result = refused
			return nil
		}

		info, err := u.live(ctx, st, now, res, cmd.Token)
		if err != nil {
			return err
		}

		result = IntrospectResult{Token: info}

		return nil
	})
	if err != nil {
		return IntrospectResult{}, fmt.Errorf("introspect: %w", err)
	}

	u.count(asked, result)

	return result, nil
}

func (u *Introspect) count(resource string, r IntrospectResult) {
	if u.Metrics == nil {
		return
	}

	switch {
	case r.Failure != nil:
		// The name belongs to a caller that was not authenticated, so it is not a label.
		u.Metrics.Introspection("unknown", "refused")
	case r.Token != nil:
		u.Metrics.Introspection(resource, "active")
	default:
		u.Metrics.Introspection(resource, "inactive")
	}
}

// live returns the facts of the token when everything it stands on is alive, and nil otherwise.
func (u *Introspect) live(ctx context.Context, st port.Stores, now time.Time, res *doidc.Resource, raw string) (*TokenInfo, error) {
	claims, err := u.Verifier.VerifyOIDCAccess(raw, res.Audience)
	if errors.Is(err, port.ErrInvalidOIDCToken) {
		// Not a user's token: it may be a service's.
		return u.liveService(ctx, st, res, raw)
	}

	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}
	// A token for a resource carries API scopes only; the one for UserInfo carries protocol scopes and has another audience.
	if len(claims.Scope) == 0 {
		return nil, nil
	}

	grant, err := st.OIDCGrants.Get(ctx, claims.GrantID)
	if errors.Is(err, port.ErrNotFound) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("load grant: %w", err)
	}

	held := grant.Resource(res.ID)
	if grant.ClientID != claims.ClientID || grant.UserID != claims.Subject || grant.OPSessionID != claims.SessionID ||
		held == nil || !covers(held.Scopes, claims.Scope) {
		return nil, nil
	}

	for _, s := range claims.Scope {
		if !res.Defines(s) {
			return nil, nil
		}
	}

	client, err := st.OIDCClients.Get(ctx, grant.ClientID)
	if errors.Is(err, port.ErrNotFound) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("load client: %w", err)
	}

	if !client.Active() {
		return nil, nil
	}

	op, _, err := u.liveGrant(ctx, st, now, grant)
	if err != nil {
		return nil, err
	}

	if op == nil {
		return nil, nil
	}

	return &TokenInfo{
		Scope: claims.Scope, ClientID: claims.ClientID, Subject: claims.Subject.String(), Audience: claims.Audience,
		JTI: claims.JTI, IssuedAt: claims.IssuedAt, ExpiresAt: claims.ExpiresAt,
	}, nil
}

// liveService answers for the token of a service identity. There is no grant behind it, so what it stands on is read afresh:
// the client is still a service and active, and still allowed every right the token carries, and the resource still
// defines them. Taking a right from a service, disabling it, or rotating its secret without an overlap ends its tokens here.
func (u *Introspect) liveService(ctx context.Context, st port.Stores, res *doidc.Resource, raw string) (*TokenInfo, error) {
	claims, err := u.Verifier.VerifyServiceAccess(raw, res.Audience)
	if errors.Is(err, port.ErrInvalidOIDCToken) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("verify service token: %w", err)
	}

	client, err := st.OIDCClients.Get(ctx, claims.ClientID)
	if errors.Is(err, port.ErrNotFound) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("load client: %w", err)
	}

	if !client.Active() || !client.Service() {
		return nil, nil
	}

	perms, err := st.OIDCResources.ClientScopes(ctx, client.ID, []string{res.ID})
	if err != nil {
		return nil, fmt.Errorf("load client resources: %w", err)
	}

	allowed, ok := perms[res.ID]
	if !ok || !covers(allowed, claims.Scope) {
		return nil, nil
	}

	for _, s := range claims.Scope {
		if !res.Defines(s) {
			return nil, nil
		}
	}

	return &TokenInfo{
		Scope: claims.Scope, ClientID: claims.ClientID, Subject: claims.ClientID, Audience: claims.Audience,
		JTI: claims.JTI, IssuedAt: claims.IssuedAt, ExpiresAt: claims.ExpiresAt,
	}, nil
}
