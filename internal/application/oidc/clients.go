package oidc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.airlance.org/auth/internal/application/port"
	doidc "go.airlance.org/auth/internal/domain/oidc"
)

type Clients struct{ Deps }

func NewClients(d Deps) (*Clients, error) {
	if d.UnitOfWork == nil || d.Clock == nil || d.Secrets == nil || d.IDs == nil {
		return nil, errors.New("new clients: all dependencies are required")
	}

	return &Clients{d}, nil
}

type RegisterCommand struct {
	ID                     string
	Name                   string
	RedirectURIs           []string
	AllowedScopes          []string
	PostLogoutRedirectURIs []string
	BackchannelLogoutURI   string
	Service                bool
	Native                 bool
}

type Registered struct {
	Client *doidc.Client
	Secret string
}

func (u *Clients) Register(ctx context.Context, cmd RegisterCommand) (Registered, error) {
	now := u.Clock.Now()

	client, err := doidc.NewClient(doidc.NewClientParams{
		ID: cmd.ID, Name: cmd.Name, RedirectURIs: cmd.RedirectURIs, AllowedScopes: cmd.AllowedScopes, Trusted: true,
		PostLogoutRedirectURIs: cmd.PostLogoutRedirectURIs, BackchannelLogoutURI: cmd.BackchannelLogoutURI, Service: cmd.Service, Native: cmd.Native,
	}, now)
	if err != nil {
		return Registered{}, fmt.Errorf("register client: %w", err)
	}

	secret, hash, err := u.Secrets.NewOIDCSecret()
	if err != nil {
		return Registered{}, fmt.Errorf("register client: %w", err)
	}

	if client.Native() {
		secret = ""
	}

	secretID, err := u.IDs.NewOIDCID()
	if err != nil {
		return Registered{}, fmt.Errorf("register client: %w", err)
	}

	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
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

		if client.Native() {
			return fmt.Errorf("%w: a native application has no logout settings", doidc.ErrInvalidClient)
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
		client, err := st.OIDCClients.Get(ctx, id)
		if err != nil {
			return err
		}

		if client.Native() {
			return fmt.Errorf("%w: a native application has no secret", doidc.ErrInvalidClient)
		}

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
