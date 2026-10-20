package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"go.airlance.org/auth/internal/adapter/clock"
	"go.airlance.org/auth/internal/adapter/crypto"
	"go.airlance.org/auth/internal/adapter/id"
	"go.airlance.org/auth/internal/adapter/metrics"
	apasskey "go.airlance.org/auth/internal/adapter/passkey"
	"go.airlance.org/auth/internal/adapter/postgres"
	appadmin "go.airlance.org/auth/internal/application/admin"
	"go.airlance.org/auth/internal/config"
	adminhttp "go.airlance.org/auth/internal/transport/http/admin"
	"go.airlance.org/auth/internal/transport/http/admin/ui"
)

// newAdmin assembles the admin API and opens its listener, the last step so that a failure
// before it leaves nothing open. The listener serves its own relying party: an operator's passkey is
// bound to the admin domain and is unknown to the users' API.
func newAdmin(cfg config.Config, logger *slog.Logger, store *postgres.Store, registry *metrics.Registry) (component, net.Addr, error) {
	web, err := apasskey.New(apasskey.Config{RPID: cfg.Admin.RPID, RPName: "Admin", Origins: cfg.Admin.Origins})
	if err != nil {
		return component{}, nil, fmt.Errorf("admin relying party: %w", err)
	}

	auth, err := appadmin.NewAuth(appadmin.AuthDeps{UnitOfWork: store, Clock: clock.System{}, WebAuthn: web, PasskeyIDs: id.Generator{}, Secrets: crypto.Ticket{}})
	if err != nil {
		return component{}, nil, err
	}

	users, err := appadmin.NewUsers(appadmin.UsersDeps{UnitOfWork: store, Clock: clock.System{}})
	if err != nil {
		return component{}, nil, err
	}

	invitations, err := appadmin.NewInvitations(appadmin.InvitationsDeps{UnitOfWork: store, Clock: clock.System{}})
	if err != nil {
		return component{}, nil, err
	}

	audit, err := appadmin.NewAudit(appadmin.AuditDeps{UnitOfWork: store, Clock: clock.System{}})
	if err != nil {
		return component{}, nil, err
	}

	handler, err := adminhttp.New(adminhttp.Deps{
		Auth: auth, Users: users, Invitations: invitations, Audit: audit,
		Logger: logger, Requests: registry, TrustedProxies: cfg.HTTP.TrustedProxies, Origins: cfg.Admin.Origins, UI: ui.Handler(),
	})
	if err != nil {
		return component{}, nil, err
	}

	ln, err := listen(cfg.Admin.Addr)
	if err != nil {
		return component{}, nil, err
	}

	srv := newHTTPServer(handler, logger)

	return component{
		name: "admin api",
		run: func(context.Context) error {
			if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
				return err
			}

			return nil
		},
		stop: srv.Shutdown,
	}, ln.Addr(), nil
}
