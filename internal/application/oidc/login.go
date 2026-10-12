package oidc

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/oidc"
)

// CompleteLogin finishes an authorization request whose browser has signed in. The page that signed the user in
// has an access token of the /v1 API for the sign-in it just made; this turns that proof, and only that, into the
// shared OP session and the code the client waits for.
type CompleteLogin struct {
	Deps
	Access port.AccessVerifier
}

// NewCompleteLogin checks the dependencies once, at assembly time.
func NewCompleteLogin(d Deps, access port.AccessVerifier) (*CompleteLogin, error) {
	if err := d.validate("complete login"); err != nil {
		return nil, err
	}
	if access == nil {
		return nil, errors.New("new complete login: an access token verifier is required")
	}
	return &CompleteLogin{Deps: d, Access: access}, nil
}

// CompleteLoginCommand is the input of CompleteLogin.
type CompleteLoginCommand struct {
	// RequestSecret is the opaque id the sign-in page was given; BindingSecret is the cookie of the browser that began.
	RequestSecret string
	BindingSecret string
	// AccessToken is the /v1 access token of the sign-in that just happened.
	AccessToken string
}

// CompleteLoginResult is the output of CompleteLogin. Exactly one of Failure and Location is set.
type CompleteLoginResult struct {
	Failure *Failure
	// Location sends the browser back to the client, with a code or with an error.
	Location string
	// SSOSecret is the value of the new OP session cookie; empty when none was opened. It lives until SSOExpiresAt.
	SSOSecret    string
	SSOExpiresAt time.Time
}

// Execute checks that the proof is fresh enough for the request, opens an OP session and issues the code. A request
// is usable once, by the browser that began it, until it expires.
func (u *CompleteLogin) Execute(ctx context.Context, cmd CompleteLoginCommand) (CompleteLoginResult, error) {
	requestHash, err := u.Secrets.HashOIDCSecret(cmd.RequestSecret)
	if err != nil {
		return CompleteLoginResult{Failure: fail(ErrInvalidRequest, "The sign-in request is not valid.")}, nil
	}
	bindingHash, err := u.Secrets.HashOIDCSecret(cmd.BindingSecret)
	if err != nil {
		return CompleteLoginResult{Failure: fail(ErrInvalidRequest, "The sign-in request is not valid.")}, nil
	}
	claims, err := u.Access.VerifyAccess(cmd.AccessToken)
	if errors.Is(err, port.ErrInvalidAccessToken) {
		return CompleteLoginResult{Failure: fail(ErrAccessDenied, "The sign-in is not valid.")}, nil
	}
	if err != nil {
		return CompleteLoginResult{}, fmt.Errorf("complete login: %w", err)
	}
	now := u.Clock.Now()

	var result CompleteLoginResult
	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		req, err := st.OIDCRequests.GetForUpdate(ctx, requestHash)
		if errors.Is(err, port.ErrNotFound) {
			result = CompleteLoginResult{Failure: fail(ErrInvalidRequest, "The sign-in request is not valid.")}
			return nil
		}
		if err != nil {
			return fmt.Errorf("load authorization request: %w", err)
		}
		if !req.Usable(now, bindingHash) {
			result = CompleteLoginResult{Failure: fail(ErrInvalidRequest, "The sign-in request expired or belongs to another browser.")}
			return nil
		}
		client, err := st.OIDCClients.Get(ctx, req.ClientID)
		if errors.Is(err, port.ErrNotFound) || (err == nil && (!client.Active() || client.Service())) {
			result = CompleteLoginResult{Failure: fail(ErrInvalidRequest, "The application is not available.")}
			return nil
		}
		if err != nil {
			return fmt.Errorf("load client: %w", err)
		}
		back := func(f *Failure) error {
			result = CompleteLoginResult{Location: redirectTo(req.RedirectURI, map[string]string{
				"error": f.Code, "error_description": f.Description, "state": req.State, "iss": u.Issuer,
			})}
			return st.OIDCRequests.Complete(ctx, requestHash, now)
		}

		// The rights over the resources may have changed while the user signed in: they are agreed again, with the
		// resources share-locked before the user, as every issuer does.
		resources, f, err := u.reagree(ctx, st, client, req)
		if err != nil {
			return err
		}
		if f != nil {
			return back(f)
		}

		// The user is locked (shared) first. A revocation of the user's sessions holds it exclusively, so what is read below
		// is either before it, and revoked with the rest, or after it, and seen as revoked.
		user, err := st.Users.GetForShare(ctx, claims.UserID)
		if errors.Is(err, port.ErrNotFound) {
			result = CompleteLoginResult{Failure: fail(ErrAccessDenied, "The sign-in is not valid.")}
			return nil
		}
		if err != nil {
			return fmt.Errorf("load user: %w", err)
		}
		// The proof must be a live session of the user it names: a token alone is not enough. It is read under the lock, so a
		// sign-out everywhere that came after the token was checked is not undone by it.
		device, err := st.Sessions.Get(ctx, claims.SessionID)
		if errors.Is(err, port.ErrNotFound) || (err == nil && (device.UserID() != claims.UserID || !device.Active(now))) {
			result = CompleteLoginResult{Failure: fail(ErrAccessDenied, "The sign-in is not valid.")}
			return nil
		}
		if err != nil {
			return fmt.Errorf("load session: %w", err)
		}
		if user.Blocked() {
			return back(fail(ErrAccessDenied, "The account cannot sign in."))
		}
		// The session's own time has the precision the token's whole seconds lack.
		if !req.Satisfied(device.AuthTime(), now) {
			result = CompleteLoginResult{Failure: fail(ErrLoginRequired, "A fresh sign-in is required.")}
			return nil
		}
		// The client's rights may have changed while the user signed in.
		if _, err := client.Grantable(req.Scopes); err != nil {
			return back(fail(ErrInvalidScope, "The application may not ask for this scope."))
		}

		secret, hash, err := u.Secrets.NewOIDCSecret()
		if err != nil {
			return fmt.Errorf("new sso cookie: %w", err)
		}
		id, err := u.IDs.NewOIDCID()
		if err != nil {
			return fmt.Errorf("new op session id: %w", err)
		}
		op := &oidc.OPSession{
			ID: id, UserID: user.ID(), SecretHash: hash, AuthTime: claims.AuthTime, AMR: slices.Clone(claims.AMR),
			CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(u.Policy.OPSessionAbsolute), DeviceSessionID: claims.SessionID.String(),
		}
		if err := st.OPSessions.Create(ctx, op); err != nil {
			return fmt.Errorf("create op session: %w", err)
		}
		if err := st.OIDCRequests.Complete(ctx, requestHash, now); err != nil {
			return fmt.Errorf("complete authorization request: %w", err)
		}
		location, err := u.issueCode(ctx, st, now, issue{
			client: client, op: op, user: user, scopes: req.Scopes, resources: resources, nonce: req.Nonce, challenge: req.CodeChallenge,
			redirectURI: req.RedirectURI, state: req.State,
		})
		if err != nil {
			return err
		}
		result = CompleteLoginResult{Location: location, SSOSecret: secret, SSOExpiresAt: op.ExpiresAt}
		return nil
	})
	if err != nil {
		return CompleteLoginResult{}, fmt.Errorf("complete login: %w", err)
	}
	return result, nil
}

// reagree settles a request that waited for a sign-in against the rights as they are now.
func (u Deps) reagree(ctx context.Context, st port.Stores, client *oidc.Client, req *oidc.AuthorizationRequest) ([]oidc.ResourceScopes, *Failure, error) {
	if len(req.Resources) == 0 {
		return nil, nil, nil
	}
	ids := make([]string, 0, len(req.Resources))
	var api []string
	for _, r := range req.Resources {
		ids = append(ids, r.ResourceID)
		for _, s := range r.Scopes {
			if !slices.Contains(api, s) {
				api = append(api, s)
			}
		}
	}
	found, err := st.OIDCResources.ByIDsForShare(ctx, ids)
	if err != nil {
		return nil, nil, fmt.Errorf("lock resources: %w", err)
	}
	agreed, f, err := u.agree(ctx, st, client, ids, found, api, func(r *oidc.Resource) string { return r.ID })
	if err != nil || f != nil {
		return nil, f, err
	}
	// Rights the client gained while the user signed in are not part of what it asked then.
	for i := range agreed {
		agreed[i].Scopes = oidc.Intersect(agreed[i].Scopes, oidc.FindResource(req.Resources, agreed[i].ResourceID).Scopes)
		if len(agreed[i].Scopes) == 0 {
			return nil, fail(ErrInvalidScope, "The application may not ask for these scopes of the resource."), nil
		}
	}
	return agreed, nil, nil
}
