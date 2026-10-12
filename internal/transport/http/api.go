package http

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"airlance.org/auth/internal/application/account"
	"airlance.org/auth/internal/application/deviceauth"
	"airlance.org/auth/internal/application/emailauth"
	appoidc "airlance.org/auth/internal/application/oidc"
	"airlance.org/auth/internal/application/passkey"
	"airlance.org/auth/internal/application/port"
	appsession "airlance.org/auth/internal/application/session"
	"airlance.org/auth/internal/transport/http/openapi"
)

const (
	// maxBodyBytes bounds a request body; every request of the contract is a few hundred bytes.
	maxBodyBytes = 16 << 10
	// readyTimeout bounds one readiness check.
	readyTimeout = 2 * time.Second
)

// ReadinessCheck reports whether the service can handle sign-in requests.
type ReadinessCheck func(ctx context.Context) error

// Deps are the dependencies of the API.
type Deps struct {
	Start   *emailauth.Start
	Resend  *emailauth.Resend
	Verify  *emailauth.VerifyCode
	Refresh *appsession.Refresh
	// The strong factor: registering a passkey, signing in with one, spending a recovery code.
	BeginEnroll  *passkey.BeginEnroll
	FinishEnroll *passkey.FinishEnroll
	BeginLogin   *passkey.BeginLogin
	FinishLogin  *passkey.FinishLogin
	Recovery     *passkey.RedeemRecovery
	// Managing the passkeys of the signed-in user, behind a step-up.
	BeginStepUp  *passkey.BeginStepUp
	FinishStepUp *passkey.FinishStepUp
	ListKeys     *passkey.ListCredentials
	RenameKey    *passkey.RenameCredential
	BeginAddKey  *passkey.BeginAddPasskey
	FinishAddKey *passkey.FinishAddPasskey
	DeleteKey    *passkey.DeleteCredential
	NewCodes     *passkey.RegenerateRecoveryCodes
	// Changing the address of the signed-in account: a step-up starts it, a code from the new address ends it.
	DeleteAccount      *account.DeleteAccount
	StartDevice        *deviceauth.Start
	StatusDevice       *deviceauth.Status
	DeviceApprover     *deviceauth.Approver
	RedeemDevice       *deviceauth.Redeem
	StartEmailChange   *account.StartEmailChange
	ConfirmEmailChange *account.ConfirmEmailChange
	// Auth checks the access token of protected routes; the rest are the session API.
	Auth      *appsession.Authenticator
	Me        *appsession.Me
	List      *appsession.ListSessions
	SignOut   *appsession.SignOut
	RevokeOne *appsession.RevokeSession
	// Apps lists and takes back the applications the user connected through the OpenID Provider.
	Apps *appoidc.Apps
	// JWKS is read once, at assembly: the key set changes only with a restart.
	JWKS  port.JWKSPublisher
	Ready ReadinessCheck
	// Metrics serves GET /metrics; nil leaves the route off, for a separate listener.
	Metrics http.Handler
	// Requests records answered requests and refusals; nil records nothing.
	Requests port.RequestMetrics
	Logger   *slog.Logger
	// TrustedProxies are the networks whose forwarding headers are believed. Empty
	// means the TCP peer is always the client.
	TrustedProxies []netip.Prefix
	// BrowserOrigins are the exact origins (scheme://host[:port]) of the pages allowed to
	// call the browser profile from another origin. Requests from the API's own origin
	// always pass; an empty list trusts no other.
	BrowserOrigins []string
	// CookieSameSite is the SameSite attribute of the browser cookies; the zero value is
	// Strict. None is for a deliberately cross-site deployment and needs BrowserOrigins.
	CookieSameSite http.SameSite
	// OIDC adds the OpenID Provider's routes to the mux; nil leaves them off. CrossOriginBypass lists the patterns
	// of its routes that other origins must be able to post to, such as "POST /oauth2/authorize".
	OIDC              RouteSet
	CrossOriginBypass []string
}

// RouteSet registers routes on a mux.
type RouteSet interface{ Routes(mux *http.ServeMux) }

// API implements the generated strict server interface.
type API struct {
	cookies cookies
	start   *emailauth.Start
	resend  *emailauth.Resend
	verify  *emailauth.VerifyCode
	refresh *appsession.Refresh

	beginEnrollUC  *passkey.BeginEnroll
	finishEnrollUC *passkey.FinishEnroll
	beginLoginUC   *passkey.BeginLogin
	finishLoginUC  *passkey.FinishLogin
	recoveryUC     *passkey.RedeemRecovery

	beginStepUpUC  *passkey.BeginStepUp
	finishStepUpUC *passkey.FinishStepUp
	listKeysUC     *passkey.ListCredentials
	renameKeyUC    *passkey.RenameCredential
	beginAddKeyUC  *passkey.BeginAddPasskey
	finishAddKeyUC *passkey.FinishAddPasskey
	deleteKeyUC    *passkey.DeleteCredential
	newCodesUC     *passkey.RegenerateRecoveryCodes

	startDeviceUC   *deviceauth.Start
	statusDeviceUC  *deviceauth.Status
	approverUC      *deviceauth.Approver
	redeemDeviceUC  *deviceauth.Redeem
	deleteAccountUC *account.DeleteAccount
	startChangeUC   *account.StartEmailChange
	confirmChangeUC *account.ConfirmEmailChange

	auth    *appsession.Authenticator
	meUC    *appsession.Me
	list    *appsession.ListSessions
	signout *appsession.SignOut
	revoke  *appsession.RevokeSession
	apps    *appoidc.Apps
	jwks    jwksDocument
	ready   ReadinessCheck
	logger  *slog.Logger
	// requests is never nil: New replaces a missing recorder with one that records nothing.
	requests port.RequestMetrics
}

var _ openapi.StrictServerInterface = (*API)(nil)

// discardRequests is the recorder of a deployment without metrics.
type discardRequests struct{}

func (discardRequests) RequestServed(string, int, time.Duration) {}
func (discardRequests) AuthDenied(string, string)                {}

// New assembles the routes of the contract, GET /metrics and the middleware.
func New(d Deps) (http.Handler, error) {
	if d.Start == nil || d.Resend == nil || d.Verify == nil || d.Refresh == nil || d.BeginStepUp == nil || d.FinishStepUp == nil || d.ListKeys == nil || d.RenameKey == nil || d.BeginAddKey == nil || d.FinishAddKey == nil || d.DeleteKey == nil || d.NewCodes == nil || d.DeleteAccount == nil || d.StartDevice == nil || d.StatusDevice == nil || d.DeviceApprover == nil || d.RedeemDevice == nil || d.StartEmailChange == nil || d.ConfirmEmailChange == nil || d.BeginEnroll == nil || d.FinishEnroll == nil || d.BeginLogin == nil || d.FinishLogin == nil || d.Recovery == nil || d.Auth == nil || d.Me == nil || d.List == nil || d.SignOut == nil || d.RevokeOne == nil || d.Apps == nil || d.JWKS == nil || d.Ready == nil || d.Logger == nil {
		return nil, errors.New("new http api: all dependencies are required")
	}
	if d.Requests == nil {
		d.Requests = discardRequests{}
	}
	jwks, err := d.JWKS.JWKS()
	if err != nil {
		return nil, fmt.Errorf("new http api: jwks: %w", err)
	}
	sameSite := d.CookieSameSite
	if sameSite == 0 {
		sameSite = http.SameSiteStrictMode
	}
	if sameSite == http.SameSiteNoneMode && len(d.BrowserOrigins) == 0 {
		return nil, errors.New("new http api: SameSite=None needs a trusted browser origin")
	}
	api := &API{
		cookies: cookies{sameSite: sameSite},
		start:   d.Start, resend: d.Resend, verify: d.Verify, refresh: d.Refresh,
		beginEnrollUC: d.BeginEnroll, finishEnrollUC: d.FinishEnroll, beginLoginUC: d.BeginLogin,
		finishLoginUC: d.FinishLogin, recoveryUC: d.Recovery,
		beginStepUpUC: d.BeginStepUp, finishStepUpUC: d.FinishStepUp, listKeysUC: d.ListKeys, renameKeyUC: d.RenameKey,
		beginAddKeyUC: d.BeginAddKey, finishAddKeyUC: d.FinishAddKey, deleteKeyUC: d.DeleteKey, newCodesUC: d.NewCodes,
		startDeviceUC: d.StartDevice, statusDeviceUC: d.StatusDevice, approverUC: d.DeviceApprover, redeemDeviceUC: d.RedeemDevice,
		deleteAccountUC: d.DeleteAccount, startChangeUC: d.StartEmailChange, confirmChangeUC: d.ConfirmEmailChange,
		auth: d.Auth, meUC: d.Me, list: d.List, signout: d.SignOut, revoke: d.RevokeOne, apps: d.Apps,
		jwks: jwks, ready: d.Ready, logger: d.Logger, requests: d.Requests,
	}

	mux := http.NewServeMux()
	strict := openapi.NewStrictHandlerWithOptions(api, nil, openapi.StrictHTTPServerOptions{
		RequestErrorHandlerFunc:  api.malformedRequest,
		ResponseErrorHandlerFunc: api.failedRequest,
	})
	openapi.HandlerWithOptions(strict, openapi.StdHTTPServerOptions{
		BaseRouter:       mux,
		ErrorHandlerFunc: api.malformedRequest,
	})
	if d.Metrics != nil {
		mux.Handle("GET /metrics", d.Metrics)
	}
	if d.OIDC != nil {
		d.OIDC.Routes(mux)
	}

	guarded, err := api.crossOrigin(d.BrowserOrigins, d.CrossOriginBypass, limitBody(noStore(logRequests(d.Logger, api.requests, mux))))
	if err != nil {
		return nil, fmt.Errorf("new http api: %w", err)
	}
	return withRequestID(withClientIP(d.TrustedProxies, withCORS(d.BrowserOrigins, withCookies(guarded)))), nil
}

// NewServer wraps handler in a server with bounded header size and read, write and idle times.
func NewServer(handler http.Handler, logger *slog.Logger) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
}
