package oidc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.airlance.org/auth/internal/application/port"
	doidc "go.airlance.org/auth/internal/domain/oidc"
)

// Clients registers and manages the clients of the provider. It runs on the server (`airlance-auth oidc client`):
// access to the server is what lets a person register an application, so none of this is reachable over HTTP.
type Clients struct{ Deps }

// NewClients checks the dependencies once, at assembly time.
func NewClients(d Deps) (*Clients, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.Secrets == nil || d.IDs == nil {
		return nil, errors.New("new clients: all dependencies are required")
	}

	return &Clients{d}, nil
}

// RegisterCommand is the input of Register.
type RegisterCommand struct {
	ID            string
	Name          string
	RedirectURIs  []string
	AllowedScopes []string
	// PostLogoutRedirectURIs and BackchannelLogoutURI are optional.
	PostLogoutRedirectURIs []string
	BackchannelLogoutURI   string
	// Service registers a service identity for the client_credentials grant instead of an application.
	Service bool
}

// Registered is the result of Register or of a rotation: the client and its secret, shown once.
type Registered struct {
	Client *doidc.Client
	Secret string
}

// Register stores a first-party client and its first secret. The secret is returned once and kept only as a hash.
func (u *Clients) Register(ctx context.Context, cmd RegisterCommand) (Registered, error) {
	now := u.Clock.Now()

	client, err := doidc.NewClient(doidc.NewClientParams{
		ID: cmd.ID, Name: cmd.Name, RedirectURIs: cmd.RedirectURIs, AllowedScopes: cmd.AllowedScopes, Trusted: true,
		PostLogoutRedirectURIs: cmd.PostLogoutRedirectURIs, BackchannelLogoutURI: cmd.BackchannelLogoutURI, Service: cmd.Service,
	}, now)
	if err != nil {
		return Registered{}, fmt.Errorf("register client: %w", err)
	}

	secret, hash, err := u.Secrets.NewOIDCSecret()
	if err != nil {
		return Registered{}, fmt.Errorf("register client: %w", err)
	}

	secretID, err := u.IDs.NewOIDCID()
	if err != nil {
		return Registered{}, fmt.Errorf("register client: %w", err)
	}

	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		// The client_id is the audience of this application's ID tokens; an API that has it for its audience would accept them.
		if taken, err := st.OIDCResources.AudienceTaken(ctx, client.ID); err != nil {
			return err
		} else if taken {
			return fmt.Errorf("%w: the identifier is the audience of a resource", doidc.ErrInvalidClient)
		}

		if err := st.OIDCClients.Create(ctx, client, secretID, hash); err != nil {
			return err
		}

		return u.audit(ctx, st, now, client.ID)
	})
	if err != nil {
		return Registered{}, fmt.Errorf("register client: %w", err)
	}

	return Registered{Client: client, Secret: secret}, nil
}

// SetLogout replaces where an application is sent after logging out and where it is told that a sign-in ended. The
// provider contacts the back-channel address from the server, so it is checked again at every delivery.
func (u *Clients) SetLogout(ctx context.Context, id string, postLogout []string, backchannel string) error {
	now := u.Clock.Now()

	err := u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		client, err := st.OIDCClients.Get(ctx, id)
		if err != nil {
			return err
		}

		if client.Service() {
			return fmt.Errorf("%w: a service signs nobody in and has no logout settings", doidc.ErrInvalidClient)
		}

		if err := client.SetLogout(postLogout, backchannel, now); err != nil {
			return err
		}

		if err := st.OIDCClients.SetLogout(ctx, id, postLogout, backchannel, now); err != nil {
			return err
		}

		return u.audit(ctx, st, now, id)
	})
	if err != nil {
		return fmt.Errorf("set client logout: %w", err)
	}

	return nil
}

// List returns every client.
func (u *Clients) List(ctx context.Context) ([]*doidc.Client, error) {
	var out []*doidc.Client

	err := u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		var err error

		out, err = st.OIDCClients.List(ctx)

		return err
	})
	if err != nil {
		return nil, fmt.Errorf("list clients: %w", err)
	}

	return out, nil
}

// SetActive enables or disables a client. Disabling also ends every grant it holds, so its tokens and refresh tokens
// stop working at once.
func (u *Clients) SetActive(ctx context.Context, id string, active bool) error {
	now := u.Clock.Now()

	status := doidc.ClientDisabled
	if active {
		status = doidc.ClientActive
	}

	err := u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if err := st.OIDCClients.SetStatus(ctx, id, status, now); err != nil {
			return err
		}

		if !active {
			if err := st.OIDCGrants.RevokeAllForClient(ctx, id, now); err != nil {
				return err
			}
		}

		return u.audit(ctx, st, now, id)
	})
	if err != nil {
		return fmt.Errorf("set client status: %w", err)
	}

	return nil
}

// RotateSecret issues a new secret. The old ones keep working for overlap, so the application can be redeployed with
// the new one; then they end.
func (u *Clients) RotateSecret(ctx context.Context, id string, overlap time.Duration) (string, error) {
	now := u.Clock.Now()

	secret, hash, err := u.Secrets.NewOIDCSecret()
	if err != nil {
		return "", fmt.Errorf("rotate client secret: %w", err)
	}

	secretID, err := u.IDs.NewOIDCID()
	if err != nil {
		return "", fmt.Errorf("rotate client secret: %w", err)
	}

	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if err := st.OIDCClients.RotateSecret(ctx, id, secretID, hash, now, overlap); err != nil {
			return err
		}

		return u.audit(ctx, st, now, id)
	})
	if err != nil {
		return "", fmt.Errorf("rotate client secret: %w", err)
	}

	return secret, nil
}

func (u *Clients) audit(ctx context.Context, st port.Stores, now time.Time, clientID string) error {
	if err := st.Audit.Record(ctx, port.AuditEvent{
		Type: port.AuditOIDCClientChanged, Result: port.AuditSuccess, At: now, Fields: map[string]string{"client": clientID},
	}); err != nil {
		return fmt.Errorf("record audit event: %w", err)
	}

	return nil
}
