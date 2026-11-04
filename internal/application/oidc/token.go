package oidc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
	doidc "go.airlance.org/auth/internal/domain/oidc"
)

// Token is the token endpoint: it exchanges an authorization code, or a refresh token, for tokens.
type Token struct{ Deps }

// NewToken checks the dependencies once, at assembly time.
func NewToken(d Deps) (*Token, error) {
	if err := d.validate("token"); err != nil {
		return nil, err
	}

	return &Token{d}, nil
}

// TokenCommand is the input of Token: the client's credentials and the grant it presents.
type TokenCommand struct {
	ClientID     string
	ClientSecret string
	GrantType    string
	Code         string
	RedirectURI  string
	CodeVerifier string
	RefreshToken string
	Scope        string
	// Resource selects the API the access token is for (RFC 8707); empty keeps the token for UserInfo. A token is for
	// one resource: the transport refuses a repeated parameter.
	Resource string
}

// TokenResponse is a successful answer. IDToken is set only when a code was exchanged, and RefreshToken is empty for a
// service (client_credentials).
type TokenResponse struct {
	AccessToken  string
	ExpiresIn    int
	IDToken      string
	RefreshToken string
	Scope        string
	// Resource selects the API the access token is for (RFC 8707); empty keeps the token for UserInfo. A token is for
	// one resource: the transport refuses a repeated parameter.
	Resource string
}

// TokenResult is the output of Token. Exactly one of Response and Failure is set. A Failure with the code
// invalid_client means the client could not be authenticated.
type TokenResult struct {
	Response *TokenResponse
	Failure  *Failure
	// Replay is set when the refusal was a replayed code or refresh token and its grant was revoked.
	Replay bool
	// Resource is the identifier of the registered resource the request named; empty when it named none, or one that is
	// not registered.
	Resource string
}

// Execute answers a token request. Every refusal is a Failure; a technical failure is an error and rolls everything
// back. A replayed code or refresh token revokes its grant and that revocation is committed with the refusal.
func (u *Token) Execute(ctx context.Context, cmd TokenCommand) (TokenResult, error) {
	now := u.Clock.Now()

	var result TokenResult

	err := u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		client, err := u.authenticateClient(ctx, st, cmd.ClientID, cmd.ClientSecret, now)
		if err != nil {
			return err
		}

		if client == nil {
			result = TokenResult{Failure: fail(ErrInvalidClient, "The client could not be authenticated.")}
			return nil
		}

		switch cmd.GrantType {
		case "authorization_code", "refresh_token":
			// A service signs nobody in: it has no codes and no refresh tokens, whatever it presents.
			if client.Service() {
				result = TokenResult{Failure: fail(ErrUnauthorizedClient, "This client may not use this grant type.")}
			} else if cmd.GrantType == "authorization_code" {
				result, err = u.exchangeCode(ctx, st, now, client, cmd)
			} else {
				result, err = u.refresh(ctx, st, now, client, cmd)
			}
		case "client_credentials":
			result, err = u.clientCredentials(ctx, st, now, client, cmd)
		default:
			result = TokenResult{Failure: fail(ErrUnsupportedGrantType, "Only authorization_code, refresh_token and client_credentials are supported.")}
		}

		return err
	})
	if err != nil {
		return TokenResult{}, fmt.Errorf("token: %w", err)
	}

	if cmd.Resource != "" && u.Metrics != nil && (result.Failure == nil || result.Failure.Code != ErrInvalidClient) {
		resource, outcome := result.Resource, "issued"
		if resource == "" {
			resource = "unknown"
		}

		if result.Failure != nil {
			outcome = result.Failure.Code
		}

		u.Metrics.ResourceToken(resource, outcome)
	}

	return result, nil
}

func (u Deps) authenticateClient(ctx context.Context, st port.Stores, id, secret string, now time.Time) (*doidc.Client, error) {
	client, err := st.OIDCClients.Get(ctx, id)
	if errors.Is(err, port.ErrNotFound) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("load client: %w", err)
	}

	if client.Native() {
		if secret != "" || !client.Active() {
			return nil, nil
		}

		return client, nil
	}

	hash, err := u.Secrets.HashOIDCSecret(secret)
	if errors.Is(err, port.ErrInvalidOIDCSecret) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("hash client secret: %w", err)
	}

	ok, err := st.OIDCClients.SecretValid(ctx, id, hash, now)
	if err != nil {
		return nil, fmt.Errorf("check client secret: %w", err)
	}

	if !ok || !client.Active() {
		return nil, nil
	}

	return client, nil
}

var errInvalidGrant = fail(ErrInvalidGrant, "The grant is not valid.")

func (u Deps) liveGrant(ctx context.Context, st port.Stores, now time.Time, grant *doidc.Grant) (*doidc.OPSession, *identity.User, error) {
	if !grant.Active(now) {
		return nil, nil, nil
	}

	op, err := st.OPSessions.Get(ctx, grant.OPSessionID)
	if errors.Is(err, port.ErrNotFound) {
		return nil, nil, nil
	}

	if err != nil {
		return nil, nil, fmt.Errorf("load op session: %w", err)
	}

	if !op.Active(now, u.Policy) {
		return nil, nil, nil
	}

	user, err := st.Users.GetForShare(ctx, grant.UserID)
	if errors.Is(err, port.ErrNotFound) {
		return nil, nil, nil
	}

	if err != nil {
		return nil, nil, fmt.Errorf("load user: %w", err)
	}

	if user.Blocked() {
		return nil, nil, nil
	}

	return op, user, nil
}

func (u Deps) exchangeCode(ctx context.Context, st port.Stores, now time.Time, client *doidc.Client, cmd TokenCommand) (result TokenResult, err error) {
	target, f, err := u.lockTarget(ctx, st, cmd.Resource)
	if err != nil {
		return TokenResult{}, err
	}

	if f != nil {
		return TokenResult{Failure: f}, nil
	}

	if target != nil {
		defer func() { result.Resource = target.ID }()
	}

	hash, err := u.Secrets.HashOIDCSecret(cmd.Code)
	if errors.Is(err, port.ErrInvalidOIDCSecret) {
		return TokenResult{Failure: errInvalidGrant}, nil
	}

	if err != nil {
		return TokenResult{}, fmt.Errorf("hash code: %w", err)
	}

	code, grant, err := st.OIDCCodes.GetByHashForUpdate(ctx, hash)
	if errors.Is(err, port.ErrNotFound) {
		return TokenResult{Failure: errInvalidGrant}, nil
	}

	if err != nil {
		return TokenResult{}, fmt.Errorf("load code: %w", err)
	}

	if grant.ClientID != client.ID {
		return TokenResult{Failure: errInvalidGrant}, nil
	}

	switch err := code.Exchange(now, cmd.RedirectURI, cmd.CodeVerifier); {
	case errors.Is(err, doidc.ErrCodeReplayed):
		if code.Matches(cmd.RedirectURI, cmd.CodeVerifier) {
			if err := u.revokeForReplay(ctx, st, now, client, grant); err != nil {
				return TokenResult{}, err
			}

			return TokenResult{Failure: errInvalidGrant, Replay: true}, nil
		}

		return TokenResult{Failure: errInvalidGrant}, nil
	case errors.Is(err, doidc.ErrRedirectMismatch), errors.Is(err, doidc.ErrPKCE):
		code.ConsumedAt = now.UTC()
		if err := st.OIDCCodes.Consume(ctx, code); err != nil {
			return TokenResult{}, fmt.Errorf("spend code: %w", err)
		}

		return TokenResult{Failure: errInvalidGrant}, nil
	case err != nil:
		return TokenResult{Failure: errInvalidGrant}, nil
	}

	op, user, err := u.liveGrant(ctx, st, now, grant)
	if err != nil {
		return TokenResult{}, err
	}

	if op == nil {
		return TokenResult{Failure: errInvalidGrant}, nil
	}

	audience, scopes := u.UserInfoAudience(), code.Scopes

	if target != nil {
		var f *Failure

		scopes, f, err = u.resourceScopes(ctx, st, client, target, intersectGrant(grant, code, target.ID), cmd.Scope)
		if err != nil {
			return TokenResult{}, err
		}

		if f != nil {
			return TokenResult{Failure: f}, nil
		}

		audience = target.Audience
	}

	if err := st.OIDCCodes.Consume(ctx, code); err != nil {
		return TokenResult{}, fmt.Errorf("consume code: %w", err)
	}

	refreshSecret, err := u.newRefresh(ctx, st, now, grant, "")
	if err != nil {
		return TokenResult{}, err
	}

	idToken, err := u.Signer.SignIDToken(port.IDTokenClaims{
		Subject: user.ID(), ClientID: client.ID, Nonce: code.Nonce, AuthTime: code.AuthTime, AMR: code.AMR, SessionID: op.ID,
		IncludeEmail: doidc.HasScope(code.Scopes, doidc.ScopeEmail), Email: user.Email().String(), EmailVerified: !user.EmailVerifiedAt().IsZero(),
	})
	if err != nil {
		return TokenResult{}, fmt.Errorf("sign id token: %w", err)
	}

	access, _, err := u.Signer.SignOIDCAccessToken(port.OIDCAccessClaims{
		Subject: user.ID(), ClientID: client.ID, Audience: audience, Scope: scopes, SessionID: op.ID, GrantID: grant.ID, AuthTime: code.AuthTime,
	})
	if err != nil {
		return TokenResult{}, fmt.Errorf("sign access token: %w", err)
	}

	if err := u.touch(ctx, st, now, grant, op); err != nil {
		return TokenResult{}, err
	}

	if err := st.Audit.Record(ctx, port.AuditEvent{
		Type: port.AuditOIDCTokensIssued, Result: port.AuditSuccess, UserID: user.ID(), At: now, Fields: tokenFields(client, target),
	}); err != nil {
		return TokenResult{}, fmt.Errorf("record audit event: %w", err)
	}

	return TokenResult{Response: &TokenResponse{
		AccessToken: access.Value, ExpiresIn: seconds(access.ExpiresAt, now), IDToken: idToken.Value, RefreshToken: refreshSecret, Scope: scopeString(scopes),
	}}, nil
}

func (u Deps) refresh(ctx context.Context, st port.Stores, now time.Time, client *doidc.Client, cmd TokenCommand) (result TokenResult, err error) {
	target, f, err := u.lockTarget(ctx, st, cmd.Resource)
	if err != nil {
		return TokenResult{}, err
	}

	if f != nil {
		return TokenResult{Failure: f}, nil
	}

	if target != nil {
		defer func() { result.Resource = target.ID }()
	}

	hash, err := u.Secrets.HashOIDCSecret(cmd.RefreshToken)
	if errors.Is(err, port.ErrInvalidOIDCSecret) {
		return TokenResult{Failure: errInvalidGrant}, nil
	}

	if err != nil {
		return TokenResult{}, fmt.Errorf("hash refresh token: %w", err)
	}

	token, grant, err := st.OIDCRefresh.GetByHashForUpdate(ctx, hash)
	if errors.Is(err, port.ErrNotFound) {
		return TokenResult{Failure: errInvalidGrant}, nil
	}

	if err != nil {
		return TokenResult{}, fmt.Errorf("load refresh token: %w", err)
	}

	if grant.ClientID != client.ID {
		return TokenResult{Failure: errInvalidGrant}, nil
	}

	scopes := grant.Scopes

	if cmd.Scope != "" && target == nil {
		asked, err := doidc.ParseScopes(cmd.Scope)
		if err != nil || !covers(grant.Scopes, asked) {
			return TokenResult{Failure: fail(ErrInvalidScope, "The scope is wider than the grant.")}, nil
		}

		scopes = asked
	}

	var lost *doidc.RefreshToken

	if err := token.Exchange(now); errors.Is(err, doidc.ErrRefreshReplayed) {
		lost, err = u.lostSuccessor(ctx, st, now, client, token)
		if err != nil {
			return TokenResult{}, err
		}

		if lost == nil {
			if err := u.revokeForReplay(ctx, st, now, client, grant); err != nil {
				return TokenResult{}, err
			}

			return TokenResult{Failure: errInvalidGrant, Replay: true}, nil
		}
	} else if err != nil {
		return TokenResult{Failure: errInvalidGrant}, nil
	}

	op, user, err := u.liveGrant(ctx, st, now, grant)
	if err != nil {
		return TokenResult{}, err
	}

	if op == nil {
		return TokenResult{Failure: errInvalidGrant}, nil
	}

	audience := u.UserInfoAudience()

	if target != nil {
		var f *Failure

		scopes, f, err = u.resourceScopes(ctx, st, client, target, grantScopes(grant, target.ID), cmd.Scope)
		if err != nil {
			return TokenResult{}, err
		}

		if f != nil {
			return TokenResult{Failure: f}, nil
		}

		audience = target.Audience
	}

	if lost != nil {
		if err := st.OIDCRefresh.Supersede(ctx, lost, now); err != nil {
			return TokenResult{}, fmt.Errorf("supersede refresh token: %w", err)
		}
	} else if err := st.OIDCRefresh.MarkUsed(ctx, token); err != nil {
		return TokenResult{}, fmt.Errorf("mark refresh token used: %w", err)
	}

	next, err := u.newRefresh(ctx, st, now, grant, token.ID)
	if err != nil {
		return TokenResult{}, err
	}

	access, _, err := u.Signer.SignOIDCAccessToken(port.OIDCAccessClaims{
		Subject: user.ID(), ClientID: client.ID, Audience: audience, Scope: scopes, SessionID: op.ID, GrantID: grant.ID, AuthTime: op.AuthTime,
	})
	if err != nil {
		return TokenResult{}, fmt.Errorf("sign access token: %w", err)
	}

	if err := u.touch(ctx, st, now, grant, op); err != nil {
		return TokenResult{}, err
	}

	if err := st.Audit.Record(ctx, port.AuditEvent{
		Type: port.AuditOIDCTokensRefresh, Result: port.AuditSuccess, UserID: user.ID(), At: now, Fields: tokenFields(client, target),
	}); err != nil {
		return TokenResult{}, fmt.Errorf("record audit event: %w", err)
	}

	return TokenResult{Response: &TokenResponse{
		AccessToken: access.Value, ExpiresIn: seconds(access.ExpiresAt, now), RefreshToken: next, Scope: scopeString(scopes),
	}}, nil
}

func (u Deps) lostSuccessor(ctx context.Context, st port.Stores, now time.Time, client *doidc.Client, token *doidc.RefreshToken) (*doidc.RefreshToken, error) {
	if !client.Native() || !token.MayRetry(now) {
		return nil, nil
	}

	next, err := st.OIDCRefresh.Successor(ctx, token.ID)
	if errors.Is(err, port.ErrNotFound) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("load refresh token successor: %w", err)
	}

	if !next.UsedAt.IsZero() || !next.RevokedAt.IsZero() {
		return nil, nil
	}

	return next, nil
}

func (u Deps) newRefresh(ctx context.Context, st port.Stores, now time.Time, grant *doidc.Grant, parentID string) (string, error) {
	secret, hash, err := u.Secrets.NewOIDCSecret()
	if err != nil {
		return "", fmt.Errorf("new refresh token: %w", err)
	}

	id, err := u.IDs.NewOIDCID()
	if err != nil {
		return "", fmt.Errorf("new refresh token id: %w", err)
	}

	token := &doidc.RefreshToken{
		ID: id, GrantID: grant.ID, Hash: hash, ParentID: parentID, CreatedAt: now, ExpiresAt: doidc.RefreshExpiry(now, u.Policy, grant),
	}
	if err := st.OIDCRefresh.Create(ctx, token); err != nil {
		return "", fmt.Errorf("store refresh token: %w", err)
	}

	return secret, nil
}

func (u Deps) touch(ctx context.Context, st port.Stores, now time.Time, grant *doidc.Grant, op *doidc.OPSession) error {
	if err := st.OIDCGrants.Touch(ctx, grant.ID, now); err != nil {
		return fmt.Errorf("touch grant: %w", err)
	}

	if err := st.OPSessions.Touch(ctx, op.ID, now); err != nil {
		return fmt.Errorf("touch op session: %w", err)
	}

	return nil
}

func (u Deps) revokeForReplay(ctx context.Context, st port.Stores, now time.Time, client *doidc.Client, grant *doidc.Grant) error {
	if err := st.OIDCGrants.Revoke(ctx, grant.ID, now); err != nil {
		return fmt.Errorf("revoke grant after replay: %w", err)
	}

	if err := st.Audit.Record(ctx, port.AuditEvent{
		Type: port.AuditOIDCReplay, Result: port.AuditDenied, UserID: grant.UserID, At: now,
		Fields: map[string]string{"client": client.ID, "reason": "token_reused"},
	}); err != nil {
		return fmt.Errorf("record audit event: %w", err)
	}

	return nil
}

func seconds(end, now time.Time) int {
	n := int(end.Sub(now) / time.Second)
	if n < 1 {
		return 1
	}

	return n
}

func (u Deps) lockTarget(ctx context.Context, st port.Stores, uri string) (*doidc.Resource, *Failure, error) {
	if uri == "" {
		return nil, nil, nil
	}

	denied := fail(ErrInvalidTarget, "The resource is not available to this application.")
	if doidc.CheckResourceURI(uri) != nil {
		return nil, denied, nil
	}

	found, err := st.OIDCResources.ByURIsForShare(ctx, []string{uri})
	if err != nil {
		return nil, nil, fmt.Errorf("lock resource: %w", err)
	}

	if len(found) != 1 || !found[0].Active() {
		return nil, denied, nil
	}

	return found[0], nil, nil
}

func grantScopes(grant *doidc.Grant, resourceID string) []string {
	if r := grant.Resource(resourceID); r != nil {
		return r.Scopes
	}

	return nil
}

func intersectGrant(grant *doidc.Grant, code *doidc.AuthorizationCode, resourceID string) []string {
	c := doidc.FindResource(code.Resources, resourceID)
	if c == nil {
		return nil
	}

	return doidc.Intersect(c.Scopes, grantScopes(grant, resourceID))
}

func (u Deps) resourceScopes(ctx context.Context, st port.Stores, client *doidc.Client, res *doidc.Resource, base []string, asked string) ([]string, *Failure, error) {
	if len(base) == 0 {
		return nil, fail(ErrInvalidTarget, "The resource is not part of this authorization."), nil
	}

	perms, err := st.OIDCResources.ClientScopes(ctx, client.ID, []string{res.ID})
	if err != nil {
		return nil, nil, fmt.Errorf("load client resources: %w", err)
	}

	allowed, ok := perms[res.ID]
	if !ok {
		return nil, fail(ErrInvalidTarget, "The resource is not available to this application."), nil
	}

	scopes := doidc.Intersect(doidc.Intersect(base, allowed), res.Scopes)

	if asked != "" {
		list, err := doidc.ParseAPIScopes(asked)
		if err != nil || !covers(scopes, list) {
			return nil, fail(ErrInvalidScope, "The scope is wider than the grant."), nil
		}

		scopes = list
	}

	if len(scopes) == 0 {
		return nil, fail(ErrInvalidScope, "The grant holds no rights of the resource any more."), nil
	}

	return scopes, nil, nil
}

func tokenFields(client *doidc.Client, res *doidc.Resource) map[string]string {
	if res == nil {
		return map[string]string{"client": client.ID}
	}

	return map[string]string{"client": client.ID, "resource": res.ID}
}

func (u Deps) clientCredentials(ctx context.Context, st port.Stores, now time.Time, client *doidc.Client, cmd TokenCommand) (result TokenResult, err error) {
	if !client.Service() {
		return TokenResult{Failure: fail(ErrUnauthorizedClient, "This client may not use this grant type.")}, nil
	}

	if cmd.Code != "" || cmd.RedirectURI != "" || cmd.CodeVerifier != "" || cmd.RefreshToken != "" {
		return TokenResult{Failure: fail(ErrInvalidRequest, "The request is not valid for this grant type.")}, nil
	}

	if cmd.Resource == "" {
		return TokenResult{Failure: fail(ErrInvalidTarget, "A resource is required.")}, nil
	}

	target, f, err := u.lockTarget(ctx, st, cmd.Resource)
	if err != nil {
		return TokenResult{}, err
	}

	if f != nil {
		return TokenResult{Failure: f}, nil
	}

	defer func() { result.Resource = target.ID }()

	perms, err := st.OIDCResources.ClientScopes(ctx, client.ID, []string{target.ID})
	if err != nil {
		return TokenResult{}, fmt.Errorf("load client resources: %w", err)
	}

	allowed, ok := perms[target.ID]
	if !ok {
		return TokenResult{Failure: fail(ErrInvalidTarget, "The resource is not available to this client.")}, nil
	}

	scopes := doidc.Intersect(allowed, target.Scopes)

	if cmd.Scope != "" {
		list, err := doidc.ParseAPIScopes(cmd.Scope)
		if err != nil || !covers(scopes, list) {
			return TokenResult{Failure: fail(ErrInvalidScope, "The scope is wider than what this client may ask.")}, nil
		}

		scopes = list
	}

	if len(scopes) == 0 {
		return TokenResult{Failure: fail(ErrInvalidScope, "This client holds no rights of the resource.")}, nil
	}

	access, _, err := u.Signer.SignServiceToken(port.ServiceAccessClaims{ClientID: client.ID, Audience: target.Audience, Scope: scopes})
	if err != nil {
		return TokenResult{}, fmt.Errorf("sign service token: %w", err)
	}

	fields := tokenFields(client, target)

	fields["reason"] = "client_credentials"
	if err := st.Audit.Record(ctx, port.AuditEvent{Type: port.AuditOIDCTokensIssued, Result: port.AuditSuccess, At: now, Fields: fields}); err != nil {
		return TokenResult{}, fmt.Errorf("record audit event: %w", err)
	}

	return TokenResult{Response: &TokenResponse{AccessToken: access.Value, ExpiresIn: seconds(access.ExpiresAt, now), Scope: scopeString(scopes)}}, nil
}
