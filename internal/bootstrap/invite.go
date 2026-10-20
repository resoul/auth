package bootstrap

import (
	"context"
	"fmt"
	"io"
	"time"

	"go.airlance.org/auth/internal/adapter/clock"
	appadmin "go.airlance.org/auth/internal/application/admin"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/config"
	"go.airlance.org/auth/internal/domain/identity"
)

// InviteAction selects what the invite command does.
type InviteAction string

// Invite actions.
const (
	InviteCreate InviteAction = "create"
	InviteList   InviteAction = "list"
	InviteRevoke InviteAction = "revoke"
)

// InviteRequest is the input of Invite. Email is used by create and revoke, TTL and NoMail by create.
type InviteRequest struct {
	Action InviteAction
	Email  string
	TTL    time.Duration
	// NoMail makes the invitation without the email that announces it.
	NoMail bool
}

// Invite manages the invitations of the invite-only registration mode against the configured
// database and reports to out. The operator runs it on the server; it is not an API.
func Invite(ctx context.Context, cfg config.Config, req InviteRequest, out io.Writer) error {
	if !cfg.Database.URL.IsSet() {
		return fmt.Errorf("%s is required for invite", config.EnvDatabaseURL)
	}

	var email identity.Email

	if req.Action != InviteList {
		var err error
		if email, err = identity.ParseEmail(req.Email); err != nil {
			return fmt.Errorf("invite: %w", err)
		}
	}

	store, err := openStore(ctx, cfg, 2)
	if err != nil {
		return err
	}
	defer store.Close()

	now := clock.System{}.Now()

	if cfg.Registration != config.RegistrationInvite {
		if _, err := fmt.Fprintf(out, "note: %s is %s, so invitations have no effect until it is %s\n", config.EnvRegistration, cfg.Registration, config.RegistrationInvite); err != nil {
			return err
		}
	}

	switch req.Action {
	case InviteCreate:
		var (
			inv        *identity.Invitation
			registered bool
		)

		err := store.Do(ctx, func(ctx context.Context, st port.Stores) error {
			var err error

			inv, registered, err = appadmin.Invite(ctx, st, email, now, req.TTL, req.NoMail)

			return err
		})
		if err != nil {
			return fmt.Errorf("invite: %w", err)
		}

		if registered {
			_, err = fmt.Fprintf(out, "%s already has an account: nothing to do\n", email)
			return err
		}

		if _, err = fmt.Fprintf(out, "invited %s until %s\n", email, inv.ExpiresAt().UTC().Format(time.RFC3339)); err != nil {
			return err
		}

		switch {
		case req.NoMail:
			_, err = fmt.Fprintln(out, "no email was queued: tell them yourself")
		case cfg.InvitationURL == "":
			_, err = fmt.Fprintf(out, "warning: %s is not set and there is no issuer, so the service will not send the invitation email\n", config.EnvInvitationURL)
		case !cfg.SMTP.Enabled():
			_, err = fmt.Fprintf(out, "the invitation email is queued; it goes out when a service with %s is running\n", config.EnvSMTPAddr)
		default:
			_, err = fmt.Fprintln(out, "the invitation email is queued and goes out through the running service")
		}

		return err
	case InviteRevoke:
		var removed bool

		err := store.Do(ctx, func(ctx context.Context, st port.Stores) error {
			var err error

			removed, err = st.Invitations.Delete(ctx, email)

			return err
		})
		if err != nil {
			return fmt.Errorf("invite: %w", err)
		}

		if !removed {
			_, err = fmt.Fprintf(out, "%s has no invitation\n", email)
			return err
		}

		_, err = fmt.Fprintf(out, "revoked the invitation of %s\n", email)

		return err
	case InviteList:
		var list []*identity.Invitation

		err := store.Do(ctx, func(ctx context.Context, st port.Stores) error {
			var err error

			list, err = st.Invitations.List(ctx)

			return err
		})
		if err != nil {
			return fmt.Errorf("invite: %w", err)
		}

		if len(list) == 0 {
			_, err = fmt.Fprintln(out, "no invitations")
			return err
		}

		for _, inv := range list {
			state := "active"
			if !inv.Active(now) {
				state = "expired"
			}

			if _, err := fmt.Fprintf(out, "%s\t%s\tinvited %s\texpires %s\n", inv.Email(), state,
				inv.CreatedAt().UTC().Format(time.RFC3339), inv.ExpiresAt().UTC().Format(time.RFC3339)); err != nil {
				return err
			}
		}

		return nil
	}

	return fmt.Errorf("invite: unknown action %q", req.Action)
}
