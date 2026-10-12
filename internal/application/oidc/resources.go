package oidc

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"airlance.org/auth/internal/application/port"
	doidc "airlance.org/auth/internal/domain/oidc"
)

// Resources registers the APIs access tokens are for and decides which client may ask what of them. It runs on the
// server (`airlance-auth oidc resource`), like the registration of clients: reaching the server is what lets a person
// widen what an application may do, so no application can widen its own access, and none of this is reachable over HTTP.
//
// Taking a right away (a resource disabled, a scope removed from it, a client's right narrowed or withdrawn) ends the
// grants that hold it, in the same transaction, and notifies their clients. Granting a right never widens a grant that
// already exists: the application asks again, and gets a new one. Every change takes the resource row first, which is what
// makes it final: a token being issued under the old rights has finished before the change, and one that comes after finds
// the new rights.
type Resources struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
	// Issuer is the origin of the provider. A resource may not take as its audience the issuer or its UserInfo, whose
	// tokens it must not be mistaken for. It may be empty where it is not known.
	Issuer string
	// Metrics counts the changes; nil counts nothing.
	Metrics port.OIDCMetrics
	// Secrets and IDs make the credentials an API introspects tokens with; RotateSecret needs them.
	Secrets port.OIDCSecrets
	IDs     port.OIDCIDGenerator
}

// NewResources checks the dependencies once, at assembly time.
func NewResources(r Resources) (*Resources, error) {
	if r.UnitOfWork == nil || r.Clock == nil {
		return nil, errors.New("new resources: all dependencies are required")
	}
	return &r, nil
}

// RegisterResourceCommand is the input of Register.
type RegisterResourceCommand struct {
	ID       string
	Name     string
	URI      string
	Audience string
	Scopes   []string
}

// Register stores a resource. Its identifier, URI and audience must be its own: another resource, an application's
// client_id and the provider's own audiences are all refused as the audience, so a token for the resource is not taken
// for one of those.
func (u *Resources) Register(ctx context.Context, cmd RegisterResourceCommand) (*doidc.Resource, error) {
	now := u.Clock.Now()
	res, err := doidc.NewResource(doidc.NewResourceParams{ID: cmd.ID, Name: cmd.Name, URI: cmd.URI, Audience: cmd.Audience, Scopes: cmd.Scopes}, now)
	if err != nil {
		return nil, fmt.Errorf("register resource: %w", err)
	}
	if u.Issuer != "" && (res.Audience == u.Issuer || res.Audience == u.Issuer+"/oauth2/userinfo") {
		return nil, fmt.Errorf("register resource: %w: the audience is the provider's own", doidc.ErrInvalidResource)
	}
	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		// A client_id is the audience of the ID tokens of that application; an API with the same audience would accept them.
		if _, err := st.OIDCClients.Get(ctx, res.Audience); err == nil {
			return fmt.Errorf("%w: the audience is the identifier of a client", doidc.ErrInvalidResource)
		} else if !errors.Is(err, port.ErrNotFound) {
			return err
		}
		if err := st.OIDCResources.Create(ctx, res); err != nil {
			return err
		}
		return u.audit(ctx, st, now, res.ID, "registered")
	})
	if err != nil {
		return nil, fmt.Errorf("register resource: %w", err)
	}
	u.counted("resource_registered", 0)
	return res, nil
}

// ResourceView is a resource with the clients that may ask for it.
type ResourceView struct {
	Resource *doidc.Resource
	Clients  []doidc.ClientResource
}

// List returns every resource with what clients may ask of it.
func (u *Resources) List(ctx context.Context) ([]ResourceView, error) {
	var out []ResourceView
	err := u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		list, err := st.OIDCResources.List(ctx)
		if err != nil {
			return err
		}
		for _, r := range list {
			clients, err := st.OIDCResources.ResourceClients(ctx, r.ID)
			if err != nil {
				return err
			}
			out = append(out, ResourceView{Resource: r, Clients: clients})
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("list resources: %w", err)
	}
	return out, nil
}

// SetActive enables or disables a resource. Disabling ends every grant that holds it and returns how many; enabling
// restores nothing: those grants stay ended and applications ask again.
func (u *Resources) SetActive(ctx context.Context, id string, active bool) (ended int, err error) {
	now := u.Clock.Now()
	status, reason := doidc.ResourceDisabled, "disabled"
	if active {
		status, reason = doidc.ResourceActive, "enabled"
	}
	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if _, err := st.OIDCResources.GetForUpdate(ctx, id); err != nil {
			return err
		}
		if err := st.OIDCResources.SetStatus(ctx, id, status, now); err != nil {
			return err
		}
		if !active {
			n, err := st.OIDCApps.RevokeOfResource(ctx, id, "", nil, now)
			if err != nil {
				return err
			}
			ended = n
		}
		return u.audit(ctx, st, now, id, reason)
	})
	if err != nil {
		return 0, fmt.Errorf("set resource status: %w", err)
	}
	u.counted("resource_"+reason, ended)
	return ended, nil
}

// SetScopes replaces the scopes a resource defines. A scope taken away is taken from every client that was allowed it,
// and ends every grant that holds it; a scope added is allowed to nobody until a client is allowed it.
func (u *Resources) SetScopes(ctx context.Context, id string, scopes []string) (ended int, err error) {
	now := u.Clock.Now()
	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		res, err := st.OIDCResources.GetForUpdate(ctx, id)
		if err != nil {
			return err
		}
		removed, err := res.SetScopes(scopes, now)
		if err != nil {
			return err
		}
		if err := st.OIDCResources.SetScopes(ctx, id, res.Scopes, now); err != nil {
			return err
		}
		if len(removed) > 0 {
			clients, err := st.OIDCResources.ResourceClients(ctx, id)
			if err != nil {
				return err
			}
			for _, c := range clients {
				kept := doidc.Intersect(c.Scopes, res.Scopes)
				if len(kept) == len(c.Scopes) {
					continue
				}
				if len(kept) == 0 {
					_, err = st.OIDCResources.DeleteClientScopes(ctx, c.ClientID, id)
				} else {
					_, err = st.OIDCResources.SetClientScopes(ctx, c.ClientID, id, kept, now)
				}
				if err != nil {
					return err
				}
			}
			if ended, err = st.OIDCApps.RevokeOfResource(ctx, id, "", removed, now); err != nil {
				return err
			}
		}
		return u.audit(ctx, st, now, id, "scopes_changed")
	})
	if err != nil {
		return 0, fmt.Errorf("set resource scopes: %w", err)
	}
	u.counted("resource_scopes_changed", ended)
	return ended, nil
}

// Allow lets a client ask for the scopes of a resource, replacing what it was allowed. Rights taken away end the grants
// of that client that hold them; rights added reach only the authorizations that come after.
func (u *Resources) Allow(ctx context.Context, clientID, resourceID string, scopes []string) (ended int, err error) {
	now := u.Clock.Now()
	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		res, err := st.OIDCResources.GetForUpdate(ctx, resourceID)
		if err != nil {
			return err
		}
		if _, err := st.OIDCClients.Get(ctx, clientID); err != nil {
			return err
		}
		if err := res.CheckPermission(scopes); err != nil {
			return err
		}
		previous, err := st.OIDCResources.SetClientScopes(ctx, clientID, resourceID, scopes, now)
		if err != nil {
			return err
		}
		if removed := missing(previous, scopes); len(removed) > 0 {
			if ended, err = st.OIDCApps.RevokeOfResource(ctx, resourceID, clientID, removed, now); err != nil {
				return err
			}
		}
		return u.audit(ctx, st, now, resourceID, "client_allowed")
	})
	if err != nil {
		return 0, fmt.Errorf("allow client resource: %w", err)
	}
	u.counted("client_allowed", ended)
	return ended, nil
}

// Deny takes every right of a resource from a client and ends the grants of the client that hold it.
func (u *Resources) Deny(ctx context.Context, clientID, resourceID string) (ended int, err error) {
	now := u.Clock.Now()
	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if _, err := st.OIDCResources.GetForUpdate(ctx, resourceID); err != nil {
			return err
		}
		previous, err := st.OIDCResources.DeleteClientScopes(ctx, clientID, resourceID)
		if err != nil {
			return err
		}
		if previous != nil {
			if ended, err = st.OIDCApps.RevokeOfResource(ctx, resourceID, clientID, nil, now); err != nil {
				return err
			}
		}
		return u.audit(ctx, st, now, resourceID, "client_denied")
	})
	if err != nil {
		return 0, fmt.Errorf("deny client resource: %w", err)
	}
	u.counted("client_denied", ended)
	return ended, nil
}

// missing returns the scopes of before that are not in after.
func missing(before, after []string) []string {
	var out []string
	for _, s := range before {
		if !slices.Contains(after, s) {
			out = append(out, s)
		}
	}
	return out
}

// counted records a change that committed.
func (u *Resources) counted(change string, ended int) {
	if u.Metrics != nil {
		u.Metrics.PermissionChange(change, ended)
	}
}

func (u *Resources) audit(ctx context.Context, st port.Stores, now time.Time, resourceID, reason string) error {
	if err := st.Audit.Record(ctx, port.AuditEvent{
		Type: port.AuditOIDCResourceChanged, Result: port.AuditSuccess, At: now, Fields: map[string]string{"resource": resourceID, "reason": reason},
	}); err != nil {
		return fmt.Errorf("record audit event: %w", err)
	}
	return nil
}

// RotateSecret issues a new introspection secret for the resource and returns it, once: only its hash is kept. The earlier
// secrets keep working for overlap, so the API can be redeployed with the new one, and then end.
func (u *Resources) RotateSecret(ctx context.Context, id string, overlap time.Duration) (string, error) {
	if u.Secrets == nil || u.IDs == nil {
		return "", errors.New("rotate resource secret: secrets and ids are required")
	}
	now := u.Clock.Now()
	secret, hash, err := u.Secrets.NewOIDCSecret()
	if err != nil {
		return "", fmt.Errorf("rotate resource secret: %w", err)
	}
	secretID, err := u.IDs.NewOIDCID()
	if err != nil {
		return "", fmt.Errorf("rotate resource secret: %w", err)
	}
	err = u.UnitOfWork.Do(ctx, func(ctx context.Context, st port.Stores) error {
		if err := st.OIDCResources.RotateSecret(ctx, id, secretID, hash, now, overlap); err != nil {
			return err
		}
		return u.audit(ctx, st, now, id, "secret_rotated")
	})
	if err != nil {
		return "", fmt.Errorf("rotate resource secret: %w", err)
	}
	return secret, nil
}
