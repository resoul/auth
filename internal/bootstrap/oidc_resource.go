package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"go.airlance.org/auth/internal/adapter/clock"
	"go.airlance.org/auth/internal/adapter/crypto"
	"go.airlance.org/auth/internal/adapter/id"
	appoidc "go.airlance.org/auth/internal/application/oidc"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/config"
)

// OIDCResourceAction selects what the oidc resource command does.
type OIDCResourceAction string

// Resource actions.
const (
	OIDCResourceRegister  OIDCResourceAction = "register"
	OIDCResourceList      OIDCResourceAction = "list"
	OIDCResourceDisable   OIDCResourceAction = "disable"
	OIDCResourceEnable    OIDCResourceAction = "enable"
	OIDCResourceSetScopes OIDCResourceAction = "set-scopes"
	OIDCResourceAllow     OIDCResourceAction = "allow"
	OIDCResourceDeny      OIDCResourceAction = "deny"
	OIDCResourceRotate    OIDCResourceAction = "rotate-secret"
)

// OIDCResourceRequest is the input of OIDCResource. ID names the resource for every action but list. Name, URI and
// Audience are used by register; Scopes by register, set-scopes and allow; ClientID by allow and deny.
type OIDCResourceRequest struct {
	Action   OIDCResourceAction
	ID       string
	Name     string
	URI      string
	Audience string
	Scopes   []string
	ClientID string
	// Overlap is how long the earlier introspection secrets keep working after rotate-secret.
	Overlap time.Duration
}

// OIDCResource manages the API resources of the OpenID Provider against the configured database and reports to out. The
// operator runs it on the server: reaching the server is what lets a person decide what an application may do, so it is
// not an API and no application can widen its own access.
func OIDCResource(ctx context.Context, cfg config.Config, req OIDCResourceRequest, out io.Writer) error {
	if !cfg.Database.URL.IsSet() {
		return fmt.Errorf("%s is required for oidc resource", config.EnvDatabaseURL)
	}

	store, err := openStore(ctx, cfg, 2)
	if err != nil {
		return err
	}
	defer store.Close()

	resources, err := appoidc.NewResources(appoidc.Resources{UnitOfWork: store, Clock: clock.System{}, Issuer: cfg.OIDC.Issuer, Secrets: crypto.OIDC{}, IDs: id.Generator{}})
	if err != nil {
		return err
	}

	gone := func(err error) error {
		if errors.Is(err, port.ErrNotFound) {
			return fmt.Errorf("no resource %q or no client %q", req.ID, req.ClientID)
		}

		return err
	}

	switch req.Action {
	case OIDCResourceRegister:
		res, err := resources.Register(ctx, appoidc.RegisterResourceCommand{ID: req.ID, Name: req.Name, URI: req.URI, Audience: req.Audience, Scopes: req.Scopes})
		if errors.Is(err, port.ErrResourceExists) {
			return fmt.Errorf("the identifier, the resource URI or the audience of %q belongs to another resource", req.ID)
		}

		if err != nil {
			return err
		}

		_, err = fmt.Fprintf(out, "registered %s\nresource: %s\naudience: %s\nscopes:   %s\nNo application may ask for it yet: allow one with `oidc resource allow`.\n",
			res.Name, res.URI, res.Audience, strings.Join(res.Scopes, " "))

		return err
	case OIDCResourceList:
		list, err := resources.List(ctx)
		if err != nil {
			return err
		}

		for _, v := range list {
			if _, err := fmt.Fprintf(out, "%s\t%s\t%s\taudience: %s\tscopes: %s\n", v.Resource.ID, v.Resource.Status, v.Resource.URI, v.Resource.Audience, strings.Join(v.Resource.Scopes, " ")); err != nil {
				return err
			}

			for _, c := range v.Clients {
				if _, err := fmt.Fprintf(out, "\tclient %s may ask: %s\n", c.ClientID, strings.Join(c.Scopes, " ")); err != nil {
					return err
				}
			}
		}

		return nil
	case OIDCResourceDisable, OIDCResourceEnable:
		ended, err := resources.SetActive(ctx, req.ID, req.Action == OIDCResourceEnable)
		if err != nil {
			return gone(err)
		}

		if req.Action == OIDCResourceEnable {
			_, err = fmt.Fprintf(out, "%s enabled; grants ended earlier stay ended and applications ask again\n", req.ID)
			return err
		}

		_, err = fmt.Fprintf(out, "%s disabled; %d grants that held it were ended and their applications notified\n", req.ID, ended)

		return err
	case OIDCResourceSetScopes:
		ended, err := resources.SetScopes(ctx, req.ID, req.Scopes)
		if err != nil {
			return gone(err)
		}

		_, err = fmt.Fprintf(out, "%s: scopes replaced; %d grants that held a removed scope were ended. A scope that was added is allowed to no application until `oidc resource allow`.\n", req.ID, ended)

		return err
	case OIDCResourceAllow:
		ended, err := resources.Allow(ctx, req.ClientID, req.ID, req.Scopes)
		if err != nil {
			return gone(err)
		}

		_, err = fmt.Fprintf(out, "%s may ask %s of %s; %d grants that held a right taken away were ended. Rights added reach new authorizations only.\n", req.ClientID, strings.Join(req.Scopes, " "), req.ID, ended)

		return err
	case OIDCResourceDeny:
		ended, err := resources.Deny(ctx, req.ClientID, req.ID)
		if err != nil {
			return gone(err)
		}

		_, err = fmt.Fprintf(out, "%s may no longer ask for %s; %d of its grants were ended\n", req.ClientID, req.ID, ended)

		return err
	case OIDCResourceRotate:
		secret, err := resources.RotateSecret(ctx, req.ID, req.Overlap)
		if err != nil {
			return gone(err)
		}

		_, err = fmt.Fprintf(out, "resource: %s\nsecret:   %s\nThe secret is shown once. The API asks %s/oauth2/introspect with the resource ID and this secret (HTTP Basic). Earlier secrets keep working for %s.\n",
			req.ID, secret, cfg.OIDC.Issuer, req.Overlap)

		return err
	}

	return errors.New("unknown oidc resource action")
}
