package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"airlance.org/auth/internal/adapter/clock"
	"airlance.org/auth/internal/adapter/crypto"
	"airlance.org/auth/internal/adapter/id"
	appoidc "airlance.org/auth/internal/application/oidc"
	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/config"
)

// OIDCClientAction selects what the oidc client command does.
type OIDCClientAction string

// Client actions.
const (
	OIDCClientCreate  OIDCClientAction = "create"
	OIDCClientList    OIDCClientAction = "list"
	OIDCClientDisable OIDCClientAction = "disable"
	OIDCClientEnable  OIDCClientAction = "enable"
	OIDCClientRotate  OIDCClientAction = "rotate-secret"
	OIDCClientLogout  OIDCClientAction = "set-logout"
)

// OIDCClientRequest is the input of OIDCClient. ID is used by every action but list; Name, RedirectURIs and Scopes by
// create; Overlap by rotate-secret.
type OIDCClientRequest struct {
	Action       OIDCClientAction
	ID           string
	Name         string
	RedirectURIs []string
	Scopes       []string
	Overlap      time.Duration
	// PostLogoutURIs and BackchannelURI are used by create and set-logout; set-logout replaces both.
	PostLogoutURIs []string
	BackchannelURI string
	// Service makes create register a service identity (client_credentials) instead of an application.
	Service bool
}

// OIDCClient manages the clients of the OpenID Provider against the configured database and reports to out. The
// operator runs it on the server: access to the server is what lets a person register an application, so it is not an
// API. A secret is printed once, here, and never again.
func OIDCClient(ctx context.Context, cfg config.Config, req OIDCClientRequest, out io.Writer) error {
	if !cfg.Database.URL.IsSet() {
		return fmt.Errorf("%s is required for oidc client", config.EnvDatabaseURL)
	}
	store, err := openStore(ctx, cfg, 2)
	if err != nil {
		return err
	}
	defer store.Close()
	clients, err := appoidc.NewClients(appoidc.Deps{UnitOfWork: store, Clock: clock.System{}, Secrets: crypto.OIDC{}, IDs: id.Generator{}})
	if err != nil {
		return err
	}

	switch req.Action {
	case OIDCClientCreate:
		got, err := clients.Register(ctx, appoidc.RegisterCommand{ID: req.ID, Name: req.Name, RedirectURIs: req.RedirectURIs, AllowedScopes: req.Scopes,
			PostLogoutRedirectURIs: req.PostLogoutURIs, BackchannelLogoutURI: req.BackchannelURI, Service: req.Service})
		if err != nil {
			return err
		}
		if req.Service {
			_, err = fmt.Fprintf(out, "registered service %s\nclient_id:     %s\nclient_secret: %s\nThe secret is shown only now. It asks for no tokens until `oidc resource allow` names an API it may call.\n",
				got.Client.Name, got.Client.ID, got.Secret)
			return err
		}
		_, err = fmt.Fprintf(out, "registered %s\nclient_id:     %s\nclient_secret: %s\nThe secret is shown only now; store it in the application's backend, never in a browser.\n",
			got.Client.Name, got.Client.ID, got.Secret)
		return err
	case OIDCClientList:
		list, err := clients.List(ctx)
		if err != nil {
			return err
		}
		for _, c := range list {
			if c.Service() {
				if _, err := fmt.Fprintf(out, "%s\t%s\tservice\n", c.ID, c.Status); err != nil {
					return err
				}
				continue
			}
			if _, err := fmt.Fprintf(out, "%s\t%s\t%s\t%s\tlogout: %s\n", c.ID, c.Status, strings.Join(c.AllowedScopes, " "), strings.Join(c.RedirectURIs, " "), logoutSummary(c.PostLogoutRedirectURIs, c.BackchannelLogoutURI)); err != nil {
				return err
			}
		}
		return nil
	case OIDCClientDisable, OIDCClientEnable:
		if err := clients.SetActive(ctx, req.ID, req.Action == OIDCClientEnable); err != nil {
			if errors.Is(err, port.ErrNotFound) {
				return fmt.Errorf("no client %q", req.ID)
			}
			return err
		}
		verb := "disabled; every grant and refresh token of it is revoked"
		if req.Action == OIDCClientEnable {
			verb = "enabled; earlier grants stay revoked and users sign in again"
		}
		_, err := fmt.Fprintf(out, "%s %s\n", req.ID, verb)
		return err
	case OIDCClientLogout:
		if err := clients.SetLogout(ctx, req.ID, req.PostLogoutURIs, req.BackchannelURI); err != nil {
			if errors.Is(err, port.ErrNotFound) {
				return fmt.Errorf("no client %q", req.ID)
			}
			return err
		}
		_, err := fmt.Fprintf(out, "%s: logout settings replaced (%d return addresses, back-channel endpoint %s)\n", req.ID, len(req.PostLogoutURIs), setOrNone(req.BackchannelURI))
		return err
	case OIDCClientRotate:
		secret, err := clients.RotateSecret(ctx, req.ID, req.Overlap)
		if errors.Is(err, port.ErrNotFound) {
			return fmt.Errorf("no client %q", req.ID)
		}
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "new client_secret: %s\nThe previous secrets work for %s more. The new one is shown only now.\n", secret, req.Overlap)
		return err
	}
	return errors.New("unknown oidc client action")
}

func setOrNone(s string) string {
	if s == "" {
		return "none"
	}
	return "set"
}

func logoutSummary(post []string, backchannel string) string {
	return fmt.Sprintf("%d return addresses, back-channel %s", len(post), setOrNone(backchannel))
}
