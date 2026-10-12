// Package oidc holds the use cases of the OpenID Provider: authorize, the sign-in that completes it, the token
// endpoint (code and refresh), UserInfo, and the registration of clients. It speaks in protocol terms (error codes,
// token responses); turning them into HTTP is the transport's job.
package oidc

import (
	"errors"
	"net/url"
	"strings"

	"airlance.org/auth/internal/application/port"
	doidc "airlance.org/auth/internal/domain/oidc"
)

// Deps are the dependencies every use case of the provider shares.
type Deps struct {
	UnitOfWork port.UnitOfWork
	Clock      port.Clock
	Secrets    port.OIDCSecrets
	IDs        port.OIDCIDGenerator
	Signer     port.OIDCSigner
	Verifier   port.OIDCAccessVerifier
	// Issuer is the origin the provider is served from, as it appears in iss.
	Issuer string
	Policy doidc.Policy
	// Metrics counts what happens to resource tokens; nil counts nothing.
	Metrics port.OIDCMetrics
}

func (d Deps) validate(name string) error {
	if d.UnitOfWork == nil || d.Clock == nil || d.Secrets == nil || d.IDs == nil || d.Signer == nil || d.Verifier == nil || d.Issuer == "" {
		return errors.New("new " + name + ": all dependencies are required")
	}
	if err := d.Policy.Validate(); err != nil {
		return errors.New("new " + name + ": " + err.Error())
	}
	return nil
}

// UserInfoAudience is the audience of the access tokens this provider issues: its own UserInfo endpoint.
func (d Deps) UserInfoAudience() string { return d.Issuer + "/oauth2/userinfo" }

// OAuth 2.0 and OpenID Connect error codes.
const (
	ErrInvalidRequest          = "invalid_request"
	ErrInvalidClient           = "invalid_client"
	ErrInvalidGrant            = "invalid_grant"
	ErrInvalidScope            = "invalid_scope"
	ErrInvalidTarget           = "invalid_target"
	ErrUnauthorizedClient      = "unauthorized_client"
	ErrUnsupportedGrantType    = "unsupported_grant_type"
	ErrUnsupportedResponseType = "unsupported_response_type"
	ErrAccessDenied            = "access_denied"
	ErrLoginRequired           = "login_required"
	ErrConsentRequired         = "consent_required"
	ErrAccountSelection        = "account_selection_required"
	ErrServerError             = "server_error"
	ErrTemporarilyUnavailable  = "temporarily_unavailable"
)

// Failure is an OAuth error to report: a code from the closed set above and a short fixed description. Descriptions
// never carry client input, secrets or the reason a check failed.
type Failure struct {
	Code        string
	Description string
}

func fail(code, description string) *Failure { return &Failure{Code: code, Description: description} }

// redirectTo builds the URL a browser is sent back to: the registered redirect URI with the response parameters
// added to its query. An empty state is left out. iss identifies the provider (RFC 9207).
func redirectTo(redirectURI string, params map[string]string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI // a registered URI always parses; it never comes from a request
	}
	q := u.Query()
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// scopeString joins scopes into the form of the scope parameter.
func scopeString(scopes []string) string { return strings.Join(scopes, " ") }
