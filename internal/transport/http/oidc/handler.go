// Package oidc is the HTTP face of the OpenID Provider: the discovery document, the key set, the authorize,
// token and UserInfo endpoints and the sign-in page. Their formats are those of OAuth 2.0 and OpenID Connect, not
// the JSON contract of the /v1 API, so they are plain net/http handlers and not generated ones.
package oidc

import (
	"embed"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	appoidc "go.airlance.org/auth/internal/application/oidc"
	"go.airlance.org/auth/internal/application/port"
	doidc "go.airlance.org/auth/internal/domain/oidc"
)

// Cookies of the provider. Both are host-only (no Domain), HttpOnly, Secure and Path=/, as the __Host- prefix makes the
// browser insist. The SSO cookie is Lax: the browser must send it on the top-level navigation from a client to
// /oauth2/authorize.
const (
	ssoCookie     = "__Host-airlance_sso"
	requestCookie = "__Host-airlance_oidc_req"
)

//go:embed web/*
var web embed.FS

// Deps are what the handlers need.
type Deps struct {
	Issuer    string
	Policy    doidc.Policy
	Authorize *appoidc.Authorize
	Login     *appoidc.CompleteLogin
	Token     *appoidc.Token
	UserInfo  *appoidc.UserInfo
	Logout    *appoidc.Logout
	Revoke    *appoidc.Revoke
	// Introspect answers the APIs that ask whether an access token is live; nil leaves the endpoint out.
	Introspect *appoidc.Introspect
	// JWKS publishes the public RS256 keys.
	JWKS     port.JWKSPublisher
	Logger   *slog.Logger
	Requests port.RequestMetrics
	Clock    port.Clock
}

// Handler serves the provider's routes.
type Handler struct {
	d         Deps
	jwks      []byte
	discovery []byte
}

// New checks the dependencies and builds the documents that never change while the process runs.
func New(d Deps) (*Handler, error) {
	if d.Issuer == "" || d.Authorize == nil || d.Login == nil || d.Token == nil || d.UserInfo == nil || d.Logout == nil || d.Revoke == nil || d.JWKS == nil || d.Logger == nil || d.Clock == nil {
		return nil, errors.New("new oidc handler: all dependencies are required")
	}

	if d.Requests == nil {
		d.Requests = discardRequests{}
	}

	keys, err := d.JWKS.JWKS()
	if err != nil {
		return nil, err
	}

	doc, err := json.Marshal(discoveryDocument(d.Issuer, d.Introspect != nil))
	if err != nil {
		return nil, err
	}

	return &Handler{d: d, jwks: keys, discovery: doc}, nil
}

type discardRequests struct{}

func (discardRequests) RequestServed(string, int, time.Duration) {}
func (discardRequests) AuthDenied(string, string)                {}

// BypassCrossOrigin lists the routes the cross-origin protection of the API must let through: the authorize endpoint
// is called by a client's page with a form post, from another origin by design, and it only starts a request that a
// browser signs in to complete.
func BypassCrossOrigin() []string { return []string{"POST /oauth2/authorize"} }

// Routes registers every route of the provider on mux, each with its own pattern so that metrics and logs name them.
func (h *Handler) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/openid-configuration", h.serveDiscovery)
	mux.HandleFunc("GET /oauth2/jwks", h.serveJWKS)
	mux.HandleFunc("GET /oauth2/authorize", h.authorize)
	mux.HandleFunc("POST /oauth2/authorize", h.authorize)
	mux.HandleFunc("POST /oauth2/token", h.token)
	mux.HandleFunc("GET /oauth2/userinfo", h.userinfo)
	mux.HandleFunc("POST /oauth2/userinfo", h.userinfo)
	mux.HandleFunc("POST /oauth2/revoke", h.revoke)

	if h.d.Introspect != nil {
		mux.HandleFunc("POST /oauth2/introspect", h.introspect)
	}

	mux.HandleFunc("GET /oauth2/logout", h.logout)
	mux.HandleFunc("POST /oauth2/logout", h.logout)
	mux.HandleFunc("GET /oauth2/login", h.loginPage)
	mux.HandleFunc("GET /oauth2/login/app.js", h.asset("web/app.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET /oauth2/login/app.css", h.asset("web/app.css", "text/css; charset=utf-8"))
	mux.HandleFunc("POST /oauth2/login/complete", h.completeLogin)
}

// discoveryDocument lists exactly what is implemented: a client that trusts it must not find a missing endpoint.
func discoveryDocument(issuer string, introspection bool) map[string]any {
	doc := map[string]any{
		"issuer":                                         issuer,
		"authorization_endpoint":                         issuer + "/oauth2/authorize",
		"token_endpoint":                                 issuer + "/oauth2/token",
		"userinfo_endpoint":                              issuer + "/oauth2/userinfo",
		"revocation_endpoint":                            issuer + "/oauth2/revoke",
		"end_session_endpoint":                           issuer + "/oauth2/logout",
		"jwks_uri":                                       issuer + "/oauth2/jwks",
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":                        []string{"public"},
		"scopes_supported":                               doidc.SupportedScopes(),
		"id_token_signing_alg_values_supported":          []string{"RS256"},
		"token_endpoint_auth_methods_supported":          []string{"client_secret_basic"},
		"revocation_endpoint_auth_methods_supported":     []string{"client_secret_basic"},
		"backchannel_logout_supported":                   true,
		"backchannel_logout_session_supported":           true,
		"code_challenge_methods_supported":               []string{"S256"},
		"claims_supported":                               []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "amr", "sid", "email", "email_verified"},
		"claim_types_supported":                          []string{"normal"},
		"request_parameter_supported":                    false,
		"request_uri_parameter_supported":                false,
		"authorization_response_iss_parameter_supported": true,
	}
	if introspection {
		doc["introspection_endpoint"] = issuer + "/oauth2/introspect"
		doc["introspection_endpoint_auth_methods_supported"] = []string{"client_secret_basic"}
	}

	return doc
}

func (h *Handler) serveDiscovery(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(h.discovery)
}

func (h *Handler) serveJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(h.jwks)
}

// noStore forbids caching of a response that carries or leads to a credential.
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

// oauthError writes a token-endpoint style error body (RFC 6749 section 5.2).
func oauthError(w http.ResponseWriter, status int, f *appoidc.Failure) {
	noStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": f.Code, "error_description": f.Description})
}

func (h *Handler) serverError(w http.ResponseWriter, r *http.Request, err error) {
	h.d.Logger.ErrorContext(r.Context(), "oidc request failed", "route", r.Pattern, "error", err)
	oauthError(w, http.StatusServiceUnavailable, &appoidc.Failure{Code: appoidc.ErrServerError, Description: "The service is temporarily unavailable."})
}

func (h *Handler) denied(r *http.Request, operation, reason string) {
	h.d.Requests.AuthDenied(operation, reason)
	h.d.Logger.DebugContext(r.Context(), "request denied", "operation", operation, "reason", reason)
}

// asset serves one embedded file of the sign-in page.
func (h *Handler) asset(name, contentType string) http.HandlerFunc {
	data, err := web.ReadFile(name)
	if err != nil {
		panic(err) // the file is part of the embed pattern
	}

	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(data)
	}
}

func (h *Handler) now() time.Time { return h.d.Clock.Now() }
