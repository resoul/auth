package bootstrap

import (
	"fmt"
	"log/slog"
	"time"

	"go.airlance.org/auth/internal/adapter/clock"
	"go.airlance.org/auth/internal/adapter/crypto"
	"go.airlance.org/auth/internal/adapter/id"
	"go.airlance.org/auth/internal/adapter/jwt"
	"go.airlance.org/auth/internal/adapter/metrics"
	"go.airlance.org/auth/internal/adapter/oidclogout"
	appoidc "go.airlance.org/auth/internal/application/oidc"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/config"
	doidc "go.airlance.org/auth/internal/domain/oidc"
	oidcapi "go.airlance.org/auth/internal/transport/http/oidc"
)

// oidcParts are what the OpenID Provider's HTTP routes and its delivery worker share.
type oidcParts struct {
	deps appoidc.Deps
	ring *jwt.RSARing
}

// newOIDCParts loads the provider's keys and builds the dependencies of its use cases. It returns nil when the provider is off.
func newOIDCParts(cfg config.Config, uow port.UnitOfWork) (*oidcParts, error) {
	if !cfg.OIDC.Enabled() {
		return nil, nil
	}

	deps, ring, err := newOIDCDeps(cfg, uow)
	if err != nil {
		return nil, err
	}

	return &oidcParts{deps: deps, ring: ring}, nil
}

// newOIDCDeps are the dependencies every use case of the OpenID Provider shares, and the keys they sign with.
func newOIDCDeps(cfg config.Config, uow port.UnitOfWork) (appoidc.Deps, *jwt.RSARing, error) {
	set := cfg.Keyring.OIDCSigning

	files := make(map[string]string, len(set.Keys))
	for kid, ref := range set.Keys {
		files[kid] = ref.KeyFile
	}

	ring, err := jwt.LoadRSARing(set.ActiveKID, files)
	if err != nil {
		return appoidc.Deps{}, nil, fmt.Errorf("load oidc keyring: %w", err)
	}

	policy := doidc.DefaultPolicy()

	tokens, err := jwt.NewOIDCTokens(ring, clock.System{}, cfg.OIDC.Issuer, policy.IDTokenTTL, policy.AccessTTL, tokenLeeway)
	if err != nil {
		return appoidc.Deps{}, nil, fmt.Errorf("create oidc token signer: %w", err)
	}

	if _, err := ring.JWKS(); err != nil {
		return appoidc.Deps{}, nil, fmt.Errorf("publish oidc jwks: %w", err)
	}

	return appoidc.Deps{
		UnitOfWork: uow, Clock: clock.System{}, Secrets: crypto.OIDC{}, IDs: id.Generator{}, Signer: tokens, Verifier: tokens,
		Issuer: cfg.OIDC.Issuer, Policy: policy,
	}, ring, nil
}

// newOIDC builds the routes of the OpenID Provider. It returns nil when the provider is off. clientRequests caps the
// token, introspection and revocation requests served at once.
func newOIDC(logger *slog.Logger, parts *oidcParts, tokens *jwtParts, registry *metrics.Registry, clientRequests int) (*oidcapi.Handler, error) {
	if parts == nil {
		return nil, nil
	}

	deps := parts.deps
	if registry != nil { // a nil *Registry must not become a non-nil interface
		deps.Metrics = registry
	}

	authorize, err := appoidc.NewAuthorize(deps)
	if err != nil {
		return nil, err
	}

	login, err := appoidc.NewCompleteLogin(deps, tokens.verifier)
	if err != nil {
		return nil, err
	}

	token, err := appoidc.NewToken(deps)
	if err != nil {
		return nil, err
	}

	userinfo, err := appoidc.NewUserInfo(deps)
	if err != nil {
		return nil, err
	}

	logout, err := appoidc.NewLogout(deps)
	if err != nil {
		return nil, err
	}

	revoke, err := appoidc.NewRevoke(deps)
	if err != nil {
		return nil, err
	}

	introspect, err := appoidc.NewIntrospect(deps)
	if err != nil {
		return nil, err
	}

	handler, err := oidcapi.New(oidcapi.Deps{
		Issuer: deps.Issuer, Policy: deps.Policy, Authorize: authorize, Login: login, Token: token, UserInfo: userinfo, Logout: logout, Revoke: revoke, Introspect: introspect,
		JWKS: parts.ring, Logger: logger, Requests: registry, Clock: clock.System{}, ClientRequests: clientRequests,
	})
	if err != nil {
		return nil, fmt.Errorf("create oidc handler: %w", err)
	}

	return handler, nil
}

// newOIDCLogoutWorker builds the worker that delivers back-channel logout notices.
func newOIDCLogoutWorker(cfg config.Config, logger *slog.Logger, parts *oidcParts) (*oidclogout.Worker, error) {
	return oidclogout.NewWorker(oidclogout.Deps{
		UnitOfWork: parts.deps.UnitOfWork, Clock: clock.System{}, Signer: parts.deps.Signer,
		HTTP: oidclogout.NewHTTPClient(cfg.OIDC.BackchannelAllow, 10*time.Second), Logger: logger, Policy: oidclogout.DefaultPolicy(),
	})
}
