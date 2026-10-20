package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
	doidc "go.airlance.org/auth/internal/domain/oidc"
)

// Authorize starts, or completes at once, an authorization request: the browser the client sent to /oauth2/authorize.
type Authorize struct{ Deps }

// NewAuthorize checks the dependencies once, at assembly time.
func NewAuthorize(d Deps) (*Authorize, error) {
	if err := d.validate("authorize"); err != nil {
		return nil, err
	}

	return &Authorize{d}, nil
}

// AuthorizeCommand is the input of Authorize. Fields hold the parameters as received; Repeated is set by the
// transport when a single-valued parameter came more than once, which is refused (after the redirect URI is trusted).
type AuthorizeCommand struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              string
	MaxAge              string
	// Resources are the values of the resource parameter (RFC 8707), which may be repeated: the APIs the application
	// will ask tokens for. None keeps the sign-in alone.
	Resources []string
	Repeated  bool
	// SSOSecret is the value of the OP session cookie, if the browser sent one.
	SSOSecret string
	// ClientIP is the address of the browser behind trusted proxies; the zero value is unknown. It is for the rate limit
	// of anonymous sign-in starts and is not stored.
	ClientIP netip.Addr
}

// Kinds of AuthorizeResult.
const (
	// AuthorizeRedirect sends the browser back to the client: with a code, or with an error.
	AuthorizeRedirect = iota + 1
	// AuthorizeLogin asks the browser to sign in. RequestID goes to the sign-in page; BindingSecret becomes a cookie.
	AuthorizeLogin
	// AuthorizeFailure shows an error on the provider itself: the client or the redirect URI cannot be trusted, so
	// the browser is not sent anywhere.
	AuthorizeFailure
)

// AuthorizeResult is the output of Authorize.
type AuthorizeResult struct {
	Kind          int
	Location      string
	RequestID     string
	BindingSecret string
	Failure       *Failure
}

// authorizeRequest is a parsed and checked command.
type authorizeRequest struct {
	// scopes are the protocol scopes; api are the rights of resources and resourceURIs the resources asked for.
	scopes       []string
	api          []string
	resourceURIs []string
	prompts      []string
	freshLogin   bool
	maxAge       *int
}

// Execute answers an authorize request. Parameter errors that can be reported to the client go back as an error
// redirect; an unknown or disabled client, or an unregistered redirect URI, is shown on the provider and the browser
// goes nowhere.
func (u *Authorize) Execute(ctx context.Context, cmd AuthorizeCommand) (AuthorizeResult, error) {
	now := u.Clock.Now()

	var result AuthorizeResult

	err := u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		client, err := st.OIDCClients.Get(ctx, cmd.ClientID)
		if errors.Is(err, port.ErrNotFound) || (err == nil && (!client.Active() || client.Service())) {
			result = AuthorizeResult{Kind: AuthorizeFailure, Failure: fail(ErrInvalidRequest, "The application is not registered.")}
			return nil
		}

		if err != nil {
			return fmt.Errorf("load client: %w", err)
		}

		if cmd.RedirectURI == "" || !client.AllowsRedirect(cmd.RedirectURI) {
			result = AuthorizeResult{Kind: AuthorizeFailure, Failure: fail(ErrInvalidRequest, "The return address is not registered for this application.")}
			return nil
		}

		back := func(f *Failure) AuthorizeResult {
			return AuthorizeResult{Kind: AuthorizeRedirect, Location: redirectTo(cmd.RedirectURI, map[string]string{
				"error": f.Code, "error_description": f.Description, "state": cmd.State, "iss": u.Issuer,
			})}
		}

		req, f := parseAuthorize(client, cmd)
		if f != nil {
			result = back(f)
			return nil
		}

		// The resources are locked (shared) before the user, in the order every issuer uses: a change of their rights
		// that has completed is seen, and one that is under way is waited for.
		resources, f, err := u.agreeResources(ctx, st, client, req.resourceURIs, req.api)
		if err != nil {
			return err
		}

		if f != nil {
			result = back(f)
			return nil
		}

		op, user, err := u.currentSession(ctx, st, cmd.SSOSecret, now)
		if err != nil {
			return err
		}

		probe := &doidc.AuthorizationRequest{FreshLogin: req.freshLogin, MaxAge: req.maxAge, CreatedAt: now}
		if op != nil && probe.Satisfied(op.AuthTime, now) {
			location, err := u.issueCode(ctx, st, now, issue{
				client: client, op: op, user: user, scopes: req.scopes, resources: resources, nonce: cmd.Nonce, challenge: cmd.CodeChallenge,
				redirectURI: cmd.RedirectURI, state: cmd.State,
			})
			if err != nil {
				return err
			}

			result = AuthorizeResult{Kind: AuthorizeRedirect, Location: location}

			return nil
		}

		if slices.Contains(req.prompts, "none") {
			result = back(fail(ErrLoginRequired, "The user is not signed in."))
			return nil
		}

		// A request row is written for a browser that has proven nothing: an address may start only so many.
		allowed, err := st.Limiter.Allow(ctx, port.Spend{Kind: port.SpendOIDC, IP: cmd.ClientIP, Now: now})
		if err != nil {
			return fmt.Errorf("spend oidc quota: %w", err)
		}

		if !allowed {
			result = back(fail(ErrTemporarilyUnavailable, "Too many sign-ins were started. Try again in a moment."))
			return nil
		}

		requestSecret, requestHash, err := u.Secrets.NewOIDCSecret()
		if err != nil {
			return fmt.Errorf("new request id: %w", err)
		}

		bindingSecret, bindingHash, err := u.Secrets.NewOIDCSecret()
		if err != nil {
			return fmt.Errorf("new request binding: %w", err)
		}

		pending := &doidc.AuthorizationRequest{
			ID: requestHash, Binding: bindingHash, ClientID: client.ID, RedirectURI: cmd.RedirectURI, Scopes: req.scopes, Resources: resources,
			State: cmd.State, Nonce: cmd.Nonce, CodeChallenge: cmd.CodeChallenge, FreshLogin: req.freshLogin, MaxAge: req.maxAge,
			CreatedAt: now, ExpiresAt: now.Add(u.Policy.RequestTTL),
		}
		if err := st.OIDCRequests.Create(ctx, pending); err != nil {
			return fmt.Errorf("store authorization request: %w", err)
		}

		result = AuthorizeResult{Kind: AuthorizeLogin, RequestID: requestSecret, BindingSecret: bindingSecret}

		return nil
	})
	if err != nil {
		return AuthorizeResult{}, fmt.Errorf("authorize: %w", err)
	}

	return result, nil
}

const maxParamLength = 512

// parseAuthorize checks everything the client controls, once its redirect URI is trusted.
func parseAuthorize(client *doidc.Client, cmd AuthorizeCommand) (*authorizeRequest, *Failure) {
	if cmd.Repeated {
		return nil, fail(ErrInvalidRequest, "A parameter was repeated.")
	}

	if cmd.ResponseType != "code" {
		return nil, fail(ErrUnsupportedResponseType, "Only the code response type is supported.")
	}

	if cmd.State == "" || len(cmd.State) > maxParamLength {
		return nil, fail(ErrInvalidRequest, "A state of up to 512 characters is required.")
	}

	if cmd.Nonce == "" || len(cmd.Nonce) > maxParamLength {
		return nil, fail(ErrInvalidRequest, "A nonce of up to 512 characters is required.")
	}

	scopes, err := doidc.ParseScopeRequest(cmd.Scope)
	if err != nil {
		return nil, fail(ErrInvalidScope, "The scope is not valid.")
	}

	if _, err := client.Grantable(scopes.Protocol); err != nil {
		return nil, fail(ErrInvalidScope, "The application may not ask for this scope.")
	}

	uris, err := doidc.ParseResourceURIs(cmd.Resources)
	if err != nil {
		return nil, fail(ErrInvalidTarget, "The resource is not valid.")
	}
	// A right of an API belongs to a resource, and a resource is asked for only with a right: the two come together.
	if (len(scopes.API) > 0) != (len(uris) > 0) {
		return nil, fail(ErrInvalidScope, "The rights of an API and the resource they are for must be asked together.")
	}

	if cmd.CodeChallengeMethod != "S256" || !doidc.ValidChallenge(cmd.CodeChallenge) {
		return nil, fail(ErrInvalidRequest, "A PKCE challenge with the S256 method is required.")
	}

	req := &authorizeRequest{scopes: scopes.Protocol, api: scopes.API, resourceURIs: uris}

	if cmd.MaxAge != "" {
		n, err := strconv.Atoi(cmd.MaxAge)
		if err != nil || n < 0 || n > 31536000 {
			return nil, fail(ErrInvalidRequest, "The max_age is not valid.")
		}

		req.maxAge = &n
		req.freshLogin = n == 0
	}

	if cmd.Prompt != "" {
		req.prompts = strings.Split(cmd.Prompt, " ")
		for i, p := range req.prompts {
			switch p {
			case "none", "login", "consent", "select_account":
			default:
				return nil, fail(ErrInvalidRequest, "The prompt is not valid.")
			}

			if slices.Contains(req.prompts[:i], p) {
				return nil, fail(ErrInvalidRequest, "The prompt is not valid.")
			}
		}

		if slices.Contains(req.prompts, "none") && len(req.prompts) > 1 {
			return nil, fail(ErrInvalidRequest, "The prompt none cannot be combined with another.")
		}

		if slices.Contains(req.prompts, "select_account") {
			return nil, fail(ErrAccountSelection, "Choosing between accounts is not supported.")
		}

		if slices.Contains(req.prompts, "consent") {
			// A trusted application's consent is implied and no screen asks for it, so it cannot be repeated on request.
			return nil, fail(ErrConsentRequired, "Consent cannot be requested again for this application.")
		}

		if slices.Contains(req.prompts, "login") {
			req.freshLogin = true
		}
	}

	return req, nil
}

// currentSession reads the OP session of the cookie and the user behind it. It is a session only if it is live, its
// user exists and is not blocked; anything else is no session. The user is share-locked, so a block or a revoke-all in
// progress is waited for and its result seen.
func (u *Authorize) currentSession(ctx context.Context, st port.Stores, secret string, now time.Time) (*doidc.OPSession, *identity.User, error) {
	return currentOPSession(ctx, st, u.Secrets, u.Policy, secret, now)
}

func currentOPSession(ctx context.Context, st port.Stores, secrets port.OIDCSecrets, policy doidc.Policy, secret string, now time.Time) (*doidc.OPSession, *identity.User, error) {
	if secret == "" {
		return nil, nil, nil
	}

	hash, err := secrets.HashOIDCSecret(secret)
	if errors.Is(err, port.ErrInvalidOIDCSecret) {
		return nil, nil, nil
	}

	if err != nil {
		return nil, nil, fmt.Errorf("hash sso cookie: %w", err)
	}

	probe, err := st.OPSessions.GetBySecret(ctx, hash)
	if errors.Is(err, port.ErrNotFound) {
		return nil, nil, nil
	}

	if err != nil {
		return nil, nil, fmt.Errorf("load op session: %w", err)
	}

	user, err := st.Users.GetForShare(ctx, probe.UserID)
	if errors.Is(err, port.ErrNotFound) {
		return nil, nil, nil
	}

	if err != nil {
		return nil, nil, fmt.Errorf("load user: %w", err)
	}
	// Read again under the lock: a revoke-all that was waited for has ended the session by now.
	op, err := st.OPSessions.Get(ctx, probe.ID)
	if errors.Is(err, port.ErrNotFound) {
		return nil, nil, nil
	}

	if err != nil {
		return nil, nil, fmt.Errorf("load op session: %w", err)
	}

	if user.Blocked() || !op.Active(now, policy) {
		return nil, nil, nil
	}

	return op, user, nil
}

// issue is what issueCode needs.
type issue struct {
	client      *doidc.Client
	op          *doidc.OPSession
	user        *identity.User
	scopes      []string
	resources   []doidc.ResourceScopes
	nonce       string
	challenge   string
	redirectURI string
	state       string
}

// issueCode finds or makes the grant of the client on the OP session, stores a one-time code and returns the URL that
// carries it back to the client. Everything happens in the caller's transaction.
func (u Deps) issueCode(ctx context.Context, st port.Stores, now time.Time, in issue) (string, error) {
	grant, err := st.OIDCGrants.FindLive(ctx, in.client.ID, in.op.ID)
	if err != nil && !errors.Is(err, port.ErrNotFound) {
		return "", fmt.Errorf("find grant: %w", err)
	}
	// A live grant is reused only while it covers what is asked and was made under the client's current rights; a
	// wider request, or a client whose rights changed, gets a new grant and a new refresh chain, never a widened one.
	if grant != nil && (!grant.Active(now) || grant.PolicyVersion != in.client.PolicyVersion || !covers(grant.Scopes, in.scopes) || !doidc.CoversResources(grant.Resources, in.resources)) {
		if err := st.OIDCGrants.Revoke(ctx, grant.ID, now); err != nil {
			return "", fmt.Errorf("revoke grant: %w", err)
		}

		grant = nil
	}

	if grant == nil {
		id, err := u.IDs.NewOIDCID()
		if err != nil {
			return "", fmt.Errorf("new grant id: %w", err)
		}

		grant = &doidc.Grant{
			ID: id, ClientID: in.client.ID, UserID: in.user.ID(), OPSessionID: in.op.ID, Scopes: slices.Clone(in.scopes), Resources: cloneResources(in.resources),
			PolicyVersion: in.client.PolicyVersion, CreatedAt: now, LastUsedAt: now, ExpiresAt: doidc.GrantExpiry(now, u.Policy, in.op),
		}
		if err := st.OIDCGrants.Create(ctx, grant); err != nil {
			return "", fmt.Errorf("create grant: %w", err)
		}
	} else if err := st.OIDCGrants.Touch(ctx, grant.ID, now); err != nil {
		return "", fmt.Errorf("touch grant: %w", err)
	}

	if err := st.OPSessions.Touch(ctx, in.op.ID, now); err != nil {
		return "", fmt.Errorf("touch op session: %w", err)
	}

	secret, hash, err := u.Secrets.NewOIDCSecret()
	if err != nil {
		return "", fmt.Errorf("new code: %w", err)
	}

	code := &doidc.AuthorizationCode{
		Hash: hash, GrantID: grant.ID, RedirectURI: in.redirectURI, CodeChallenge: in.challenge, Nonce: in.nonce,
		Scopes: slices.Clone(in.scopes), Resources: cloneResources(in.resources), AuthTime: in.op.AuthTime, AMR: slices.Clone(in.op.AMR), CreatedAt: now, ExpiresAt: now.Add(u.Policy.CodeTTL),
	}
	if err := st.OIDCCodes.Create(ctx, code); err != nil {
		return "", fmt.Errorf("store code: %w", err)
	}

	if err := st.Audit.Record(ctx, port.AuditEvent{
		Type: port.AuditOIDCCodeIssued, Result: port.AuditSuccess, UserID: in.user.ID(), At: now, Fields: map[string]string{"client": in.client.ID},
	}); err != nil {
		return "", fmt.Errorf("record audit event: %w", err)
	}

	return redirectTo(in.redirectURI, map[string]string{"code": secret, "state": in.state, "iss": u.Issuer}), nil
}

func covers(granted, asked []string) bool {
	for _, s := range asked {
		if !slices.Contains(granted, s) {
			return false
		}
	}

	return true
}

func cloneResources(list []doidc.ResourceScopes) []doidc.ResourceScopes {
	if len(list) == 0 {
		return nil
	}

	out := make([]doidc.ResourceScopes, len(list))
	for i, r := range list {
		out[i] = doidc.ResourceScopes{ResourceID: r.ResourceID, PolicyVersion: r.PolicyVersion, Scopes: slices.Clone(r.Scopes)}
	}

	return out
}

// agreeResources settles what an authorization request may have of the resources it names: each must be registered,
// active and open to the client, and the rights asked must be ones the client was allowed and the resource still
// defines. The resources are share-locked in the order of their IDs. A refusal never says which of those it was.
func (u Deps) agreeResources(ctx context.Context, st port.Stores, client *doidc.Client, uris, api []string) ([]doidc.ResourceScopes, *Failure, error) {
	if len(uris) == 0 {
		return nil, nil, nil
	}

	found, err := st.OIDCResources.ByURIsForShare(ctx, uris)
	if err != nil {
		return nil, nil, fmt.Errorf("lock resources: %w", err)
	}

	return u.agree(ctx, st, client, uris, found, api, func(r *doidc.Resource) string { return r.URI })
}

// agree is the part of agreeResources and of the completion of a sign-in that the two share: the resources asked, in the
// order asked, are looked up in what was found.
func (u Deps) agree(ctx context.Context, st port.Stores, client *doidc.Client, asked []string, found []*doidc.Resource, api []string, key func(*doidc.Resource) string) ([]doidc.ResourceScopes, *Failure, error) {
	denied := fail(ErrInvalidTarget, "The resource is not available to this application.")
	list := make([]*doidc.Resource, 0, len(asked))

	ids := make([]string, 0, len(asked))
	for _, a := range asked {
		i := slices.IndexFunc(found, func(r *doidc.Resource) bool { return key(r) == a })
		if i < 0 || !found[i].Active() {
			return nil, denied, nil
		}

		list = append(list, found[i])
		ids = append(ids, found[i].ID)
	}

	perms, err := st.OIDCResources.ClientScopes(ctx, client.ID, ids)
	if err != nil {
		return nil, nil, fmt.Errorf("load client resources: %w", err)
	}

	agreed, err := doidc.AgreeScopes(list, perms, api)
	switch {
	case errors.Is(err, doidc.ErrInvalidTarget):
		return nil, denied, nil
	case err != nil:
		return nil, fail(ErrInvalidScope, "The application may not ask for these scopes of the resource."), nil
	}

	return agreed, nil, nil
}
