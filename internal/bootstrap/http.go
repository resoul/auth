package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"

	"airlance.org/auth/internal/adapter/clock"
	"airlance.org/auth/internal/adapter/crypto"
	"airlance.org/auth/internal/adapter/id"
	"airlance.org/auth/internal/adapter/metrics"
	apasskey "airlance.org/auth/internal/adapter/passkey"
	"airlance.org/auth/internal/adapter/postgres"
	"airlance.org/auth/internal/application/account"
	"airlance.org/auth/internal/application/deviceauth"
	"airlance.org/auth/internal/application/emailauth"
	appoidc "airlance.org/auth/internal/application/oidc"
	"airlance.org/auth/internal/application/passkey"
	appsession "airlance.org/auth/internal/application/session"
	"airlance.org/auth/internal/config"
	"airlance.org/auth/internal/domain/authflow"
	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/domain/session"
	httpapi "airlance.org/auth/internal/transport/http"
	oidcapi "airlance.org/auth/internal/transport/http/oidc"
)

// newHTTP assembles the use cases behind the API and opens its listener.
// The listener is opened last, so a failure before it leaves nothing open.
func newHTTP(cfg config.Config, logger *slog.Logger, otp *crypto.OTP, tokens *jwtParts, store *postgres.Store, registry *metrics.Registry, oidcParts *oidcParts) (component, net.Addr, error) {
	if otp == nil || tokens == nil {
		return component{}, nil, errors.New("http api needs the otp_hmac and jwt_signing keys")
	}
	flowPolicy, sessionPolicy := authflow.DefaultPolicy(), session.DefaultPolicy()
	// A configuration not made by Load has no mode; that is the open one, like an unset variable.
	mode := cfg.Registration
	if mode == "" {
		mode = config.RegistrationOpen
	}
	registration, err := identity.ParseRegistrationMode(mode)
	if err != nil {
		return component{}, nil, err
	}

	start, err := emailauth.NewStart(emailauth.StartDeps{
		UnitOfWork: store, Clock: clock.System{}, FlowIDs: crypto.Random{}, OTP: otp, Bindings: crypto.Binding{}, Policy: flowPolicy, Registration: registration,
	})
	if err != nil {
		return component{}, nil, err
	}
	resend, err := emailauth.NewResend(emailauth.ResendDeps{
		UnitOfWork: store, Clock: clock.System{}, OTP: otp, Bindings: crypto.Binding{}, Policy: flowPolicy, Registration: registration,
	})
	if err != nil {
		return component{}, nil, err
	}
	issuer, err := appsession.NewIssuer(appsession.IssuerDeps{
		SessionIDs: id.Generator{}, TokenIDs: id.Generator{}, Secrets: crypto.Refresh{}, Policy: sessionPolicy,
	})
	if err != nil {
		return component{}, nil, err
	}
	verify, err := emailauth.NewVerifyCode(emailauth.VerifyCodeDeps{
		UnitOfWork: store, Clock: clock.System{}, OTP: otp, Bindings: crypto.Binding{}, UserIDs: id.Generator{},
		RecognizedIDs: id.Generator{}, PasskeyIDs: id.Generator{}, Tickets: crypto.Ticket{}, Policy: flowPolicy, Registration: registration,
	})
	if err != nil {
		return component{}, nil, err
	}
	web, err := apasskey.New(apasskey.Config{RPID: cfg.WebAuthn.RPID, RPName: cfg.WebAuthn.RPName, Origins: cfg.WebAuthn.Origins})
	if err != nil {
		return component{}, nil, err
	}
	signedIn := passkey.SessionDeps{Sessions: issuer, Signer: tokens.signer}
	beginEnroll, err := passkey.NewBeginEnroll(passkey.BeginEnrollDeps{
		UnitOfWork: store, Clock: clock.System{}, WebAuthn: web, Bindings: crypto.Binding{}, Tickets: crypto.Ticket{}, PasskeyIDs: id.Generator{},
	})
	if err != nil {
		return component{}, nil, err
	}
	finishEnroll, err := passkey.NewFinishEnroll(passkey.FinishEnrollDeps{
		UnitOfWork: store, Clock: clock.System{}, WebAuthn: web, Bindings: crypto.Binding{}, Tickets: crypto.Ticket{},
		PasskeyIDs: id.Generator{}, Recovery: crypto.Recovery{}, SessionDeps: signedIn,
	})
	if err != nil {
		return component{}, nil, err
	}
	beginLogin, err := passkey.NewBeginLogin(passkey.BeginLoginDeps{UnitOfWork: store, Clock: clock.System{}, WebAuthn: web, PasskeyIDs: id.Generator{}})
	if err != nil {
		return component{}, nil, err
	}
	finishLogin, err := passkey.NewFinishLogin(passkey.FinishLoginDeps{
		UnitOfWork: store, Clock: clock.System{}, WebAuthn: web, Bindings: crypto.Binding{}, Tickets: crypto.Ticket{}, SessionDeps: signedIn,
	})
	if err != nil {
		return component{}, nil, err
	}
	recovery, err := passkey.NewRedeemRecovery(passkey.RedeemRecoveryDeps{
		UnitOfWork: store, Clock: clock.System{}, Bindings: crypto.Binding{}, Tickets: crypto.Ticket{}, Recovery: crypto.Recovery{}, PasskeyIDs: id.Generator{},
	})
	if err != nil {
		return component{}, nil, err
	}
	refresh, err := appsession.NewRefresh(appsession.RefreshDeps{
		UnitOfWork: store, Clock: clock.System{}, TokenIDs: id.Generator{}, Secrets: crypto.Refresh{},
		Metrics: registry, Signer: tokens.signer, Policy: sessionPolicy,
	})
	if err != nil {
		return component{}, nil, err
	}
	auth, err := appsession.NewAuthenticator(appsession.AuthenticateDeps{UnitOfWork: store, Clock: clock.System{}, Verifier: tokens.verifier})
	if err != nil {
		return component{}, nil, err
	}
	reads := appsession.ReadDeps{UnitOfWork: store, Clock: clock.System{}}
	me, err := appsession.NewMe(reads)
	if err != nil {
		return component{}, nil, err
	}
	list, err := appsession.NewListSessions(reads)
	if err != nil {
		return component{}, nil, err
	}
	revokes := appsession.RevokeDeps{UnitOfWork: store, Clock: clock.System{}}
	signOut, err := appsession.NewSignOut(revokes)
	if err != nil {
		return component{}, nil, err
	}
	revokeOne, err := appsession.NewRevokeSession(revokes)
	if err != nil {
		return component{}, nil, err
	}
	manage := passkey.ManageDeps{UnitOfWork: store, Clock: clock.System{}}
	listKeys, err := passkey.NewListCredentials(manage)
	if err != nil {
		return component{}, nil, err
	}
	renameKey, err := passkey.NewRenameCredential(manage)
	if err != nil {
		return component{}, nil, err
	}
	beginStepUp, err := passkey.NewBeginStepUp(passkey.BeginStepUpDeps{UnitOfWork: store, Clock: clock.System{}, WebAuthn: web, PasskeyIDs: id.Generator{}})
	if err != nil {
		return component{}, nil, err
	}
	finishStepUp, err := passkey.NewFinishStepUp(passkey.FinishStepUpDeps{UnitOfWork: store, Clock: clock.System{}, WebAuthn: web, Tickets: crypto.Ticket{}, PasskeyIDs: id.Generator{}})
	if err != nil {
		return component{}, nil, err
	}
	beginAddKey, err := passkey.NewBeginAddPasskey(passkey.BeginAddPasskeyDeps{UnitOfWork: store, Clock: clock.System{}, WebAuthn: web, Tickets: crypto.Ticket{}, PasskeyIDs: id.Generator{}})
	if err != nil {
		return component{}, nil, err
	}
	finishAddKey, err := passkey.NewFinishAddPasskey(passkey.FinishAddPasskeyDeps{UnitOfWork: store, Clock: clock.System{}, WebAuthn: web, Tickets: crypto.Ticket{}, PasskeyIDs: id.Generator{}})
	if err != nil {
		return component{}, nil, err
	}
	deleteKey, err := passkey.NewDeleteCredential(passkey.DeleteCredentialDeps{UnitOfWork: store, Clock: clock.System{}, Tickets: crypto.Ticket{}})
	if err != nil {
		return component{}, nil, err
	}
	newCodes, err := passkey.NewRegenerateRecoveryCodes(passkey.RegenerateRecoveryCodesDeps{
		UnitOfWork: store, Clock: clock.System{}, Tickets: crypto.Ticket{}, Recovery: crypto.Recovery{}, PasskeyIDs: id.Generator{},
	})
	if err != nil {
		return component{}, nil, err
	}

	startEmailChange, err := account.NewStartEmailChange(account.StartEmailChangeDeps{
		UnitOfWork: store, Clock: clock.System{}, FlowIDs: crypto.Random{}, OTP: otp, Tickets: crypto.Ticket{}, Policy: flowPolicy,
	})
	if err != nil {
		return component{}, nil, err
	}
	confirmEmailChange, err := account.NewConfirmEmailChange(account.ConfirmEmailChangeDeps{
		UnitOfWork: store, Clock: clock.System{}, OTP: otp, Policy: flowPolicy,
	})
	if err != nil {
		return component{}, nil, err
	}

	startDevice, err := deviceauth.NewStart(deviceauth.StartDeps{
		UnitOfWork: store, Clock: clock.System{}, Secrets: crypto.Device{}, Tickets: crypto.Ticket{}, Bindings: crypto.Binding{},
	})
	if err != nil {
		return component{}, nil, err
	}
	statusDevice, err := deviceauth.NewStatus(deviceauth.StatusDeps{UnitOfWork: store, Clock: clock.System{}, Tickets: crypto.Ticket{}, Bindings: crypto.Binding{}})
	if err != nil {
		return component{}, nil, err
	}
	deviceApprover, err := deviceauth.NewApprover(deviceauth.ApproveDeps{UnitOfWork: store, Clock: clock.System{}, Tickets: crypto.Ticket{}})
	if err != nil {
		return component{}, nil, err
	}
	redeemDevice, err := deviceauth.NewRedeem(deviceauth.RedeemDeps{
		UnitOfWork: store, Clock: clock.System{}, Tickets: crypto.Ticket{}, Bindings: crypto.Binding{}, SessionDeps: signedIn,
	})
	if err != nil {
		return component{}, nil, err
	}

	deleteAccount, err := account.NewDeleteAccount(account.DeleteAccountDeps{UnitOfWork: store, Clock: clock.System{}, Tickets: crypto.Ticket{}})
	if err != nil {
		return component{}, nil, err
	}

	// A separate metrics listener takes /metrics off the API port.
	var metricsHandler http.Handler
	if !cfg.Metrics.Enabled() {
		metricsHandler = registry.Handler()
	}
	appsDeps := appoidc.Apps{UnitOfWork: store, Clock: clock.System{}}
	if registry != nil { // a nil *Registry must not become a non-nil interface
		appsDeps.Metrics = registry
	}
	apps, err := appoidc.NewApps(appsDeps)
	if err != nil {
		return component{}, nil, err
	}
	oidcRoutes, err := newOIDC(logger, oidcParts, tokens, registry)
	if err != nil {
		return component{}, nil, err
	}
	deps := httpapi.Deps{
		Start: start, Resend: resend, Verify: verify, Refresh: refresh, JWKS: tokens.ring,
		BeginEnroll: beginEnroll, FinishEnroll: finishEnroll, BeginLogin: beginLogin, FinishLogin: finishLogin, Recovery: recovery,
		BeginStepUp: beginStepUp, FinishStepUp: finishStepUp, ListKeys: listKeys, RenameKey: renameKey,
		BeginAddKey: beginAddKey, FinishAddKey: finishAddKey, DeleteKey: deleteKey, NewCodes: newCodes,
		DeleteAccount: deleteAccount, StartDevice: startDevice, StatusDevice: statusDevice, DeviceApprover: deviceApprover, RedeemDevice: redeemDevice, StartEmailChange: startEmailChange, ConfirmEmailChange: confirmEmailChange,
		Auth: auth, Me: me, List: list, SignOut: signOut, RevokeOne: revokeOne, Apps: apps,
		Ready: store.Ping, Metrics: metricsHandler, Requests: registry, Logger: logger, TrustedProxies: cfg.HTTP.TrustedProxies,
		BrowserOrigins: cfg.HTTP.BrowserOrigins, CookieSameSite: sameSite(cfg.HTTP.CookieSameSite),
	}
	if oidcRoutes != nil {
		// A nil *Handler must not become a non-nil interface: the routes are added only when the provider is on.
		deps.OIDC, deps.CrossOriginBypass = oidcRoutes, oidcapi.BypassCrossOrigin()
	}
	handler, err := httpapi.New(deps)
	if err != nil {
		return component{}, nil, err
	}

	ln, err := listen(cfg.HTTP.Addr)
	if err != nil {
		return component{}, nil, err
	}
	srv := newHTTPServer(handler, logger)
	return component{
		name: "http api",
		run: func(context.Context) error {
			if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
				return err
			}
			return nil
		},
		// Shutdown closes the listener and waits for requests in flight.
		stop: srv.Shutdown,
	}, ln.Addr(), nil
}

func sameSite(value string) http.SameSite {
	switch value {
	case config.SameSiteLax:
		return http.SameSiteLaxMode
	case config.SameSiteNone:
		return http.SameSiteNoneMode
	}
	return http.SameSiteStrictMode
}

// listen opens the TCP listener. Config has checked the address and, beyond the loopback, that a proxy is trusted.
func listen(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", addr, err)
	}
	return ln, nil
}

// newHTTPServer wraps a handler in the server both the API and the admin listener use: bounded header size
// and read, write and idle times.
func newHTTPServer(handler http.Handler, logger *slog.Logger) *http.Server {
	return httpapi.NewServer(handler, logger)
}
