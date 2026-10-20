package oidc

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

// A client identifier is also an audit value, so it uses only lower-case letters, digits, '-' and '_'.
var clientIDShape = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,63}$`)

// Client statuses.
const (
	ClientActive   = "active"
	ClientDisabled = "disabled"
)

const (
	maxRedirects   = 10
	maxRedirectLen = 2048
)

// Client kinds.
const (
	// ClientApplication is an application a person signs in to: a confidential web client with a backend,
	// authenticating with client_secret_basic and PKCE.
	ClientApplication = "application"
	// ClientService is a service that calls APIs in its own name (the client_credentials grant). It signs nobody in.
	ClientService = "service"
)

// Client is a registered client: an application with a backend, or a service. Both authenticate with client_secret_basic.
type Client struct {
	ID   string
	Name string
	// Kind is ClientApplication or ClientService.
	Kind         string
	Status       string
	RedirectURIs []string
	// PostLogoutRedirectURIs are where the browser may be sent after RP-initiated logout; matched exactly.
	PostLogoutRedirectURIs []string
	// BackchannelLogoutURI is where the provider tells the client's backend that a sign-in ended; empty for none.
	BackchannelLogoutURI string
	AllowedScopes        []string
	// Trusted marks a first-party application whose users are not asked for consent. Only trusted clients exist yet.
	Trusted       bool
	PolicyVersion int
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// ParseClientID validates a client identifier.
func ParseClientID(s string) (string, error) {
	if !clientIDShape.MatchString(s) {
		return "", ErrInvalidClientID
	}

	return s, nil
}

// NewClientParams are the inputs of NewClient.
type NewClientParams struct {
	ID            string
	Name          string
	RedirectURIs  []string
	AllowedScopes []string
	Trusted       bool
	// PostLogoutRedirectURIs and BackchannelLogoutURI are optional; they follow the rules of redirect URIs.
	PostLogoutRedirectURIs []string
	BackchannelLogoutURI   string
	// Service registers a service identity: no redirect addresses, scopes or logout settings, only a name and a secret.
	Service bool
}

// NewClient validates a registration. Redirect URIs are matched exactly later, so they must be exact now: absolute,
// https (http only for loopback and localhost, for development), no fragment, no user information, no wildcard.
func NewClient(p NewClientParams, now time.Time) (*Client, error) {
	if _, err := ParseClientID(p.ID); err != nil {
		return nil, err
	}

	if p.Name == "" || len(p.Name) > 100 {
		return nil, fmt.Errorf("%w: a name of 1 to 100 characters is required", ErrInvalidClient)
	}

	if p.Service {
		if len(p.RedirectURIs) > 0 || len(p.AllowedScopes) > 0 || len(p.PostLogoutRedirectURIs) > 0 || p.BackchannelLogoutURI != "" {
			return nil, fmt.Errorf("%w: a service has no redirect URIs, scopes or logout settings", ErrInvalidClient)
		}

		if !p.Trusted {
			return nil, fmt.Errorf("%w: only first-party services can be registered", ErrInvalidClient)
		}

		return &Client{ID: p.ID, Name: p.Name, Kind: ClientService, Status: ClientActive, Trusted: true, PolicyVersion: 1, CreatedAt: now.UTC(), UpdatedAt: now.UTC()}, nil
	}

	if !p.Trusted {
		return nil, fmt.Errorf("%w: consent for third-party clients is not implemented; only trusted (first-party) clients can be registered", ErrInvalidClient)
	}

	if len(p.RedirectURIs) == 0 || len(p.RedirectURIs) > maxRedirects {
		return nil, fmt.Errorf("%w: 1 to %d redirect URIs are required", ErrInvalidClient, maxRedirects)
	}

	for i, uri := range p.RedirectURIs {
		if err := checkRedirectURI(uri); err != nil {
			return nil, fmt.Errorf("%w: redirect URI %d: %w", ErrInvalidClient, i+1, err)
		}

		if slices.Contains(p.RedirectURIs[:i], uri) {
			return nil, fmt.Errorf("%w: redirect URI %d is repeated", ErrInvalidClient, i+1)
		}
	}

	if err := checkLogoutURIs(p.PostLogoutRedirectURIs, p.BackchannelLogoutURI); err != nil {
		return nil, err
	}

	scopes := p.AllowedScopes
	if len(scopes) == 0 {
		scopes = []string{ScopeOpenID, ScopeEmail}
	}

	for i, s := range scopes {
		if !slices.Contains(SupportedScopes(), s) || slices.Contains(scopes[:i], s) {
			return nil, fmt.Errorf("%w: scope %q", ErrInvalidScope, s)
		}
	}

	if !slices.Contains(scopes, ScopeOpenID) {
		return nil, fmt.Errorf("%w: the openid scope is required", ErrInvalidClient)
	}

	return &Client{
		ID: p.ID, Name: p.Name, Kind: ClientApplication, Status: ClientActive, RedirectURIs: slices.Clone(p.RedirectURIs),
		AllowedScopes: slices.Clone(scopes), Trusted: p.Trusted, PolicyVersion: 1,
		PostLogoutRedirectURIs: slices.Clone(p.PostLogoutRedirectURIs), BackchannelLogoutURI: p.BackchannelLogoutURI, CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
	}, nil
}

func checkRedirectURI(raw string) error {
	if raw == "" || len(raw) > maxRedirectLen || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "*\\\r\n\t ") {
		return fmt.Errorf("not a plain absolute URL")
	}

	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" || u.Opaque != "" {
		return fmt.Errorf("not an absolute URL")
	}

	if u.User != nil {
		return fmt.Errorf("must not carry credentials")
	}

	if u.Fragment != "" || strings.Contains(raw, "#") {
		return fmt.Errorf("must not have a fragment")
	}

	switch u.Scheme {
	case "https":
	case "http":
		if ip := net.ParseIP(u.Hostname()); u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return fmt.Errorf("http is allowed for localhost and loopback addresses only")
		}
	default:
		return fmt.Errorf("must be https")
	}

	return nil
}

// Active reports whether the client may start new sign-ins.
func (c *Client) Active() bool { return c.Status == ClientActive }

// Service reports whether the client is a service identity, which signs nobody in.
func (c *Client) Service() bool { return c.Kind == ClientService }

// AllowsRedirect reports whether uri is registered, compared exactly: no normalization, no prefix, no pattern.
func (c *Client) AllowsRedirect(uri string) bool { return slices.Contains(c.RedirectURIs, uri) }

// Grantable returns the requested scopes if every one is allowed to the client, else ErrInvalidScope.
func (c *Client) Grantable(requested []string) ([]string, error) {
	for _, s := range requested {
		if !slices.Contains(c.AllowedScopes, s) {
			return nil, ErrInvalidScope
		}
	}

	return requested, nil
}

// checkLogoutURIs checks the addresses of logout: the same rules as for redirect URIs, and at most ten.
func checkLogoutURIs(postLogout []string, backchannel string) error {
	if len(postLogout) > maxRedirects {
		return fmt.Errorf("%w: at most %d post-logout redirect URIs", ErrInvalidClient, maxRedirects)
	}

	for i, uri := range postLogout {
		if err := checkRedirectURI(uri); err != nil {
			return fmt.Errorf("%w: post-logout redirect URI %d: %w", ErrInvalidClient, i+1, err)
		}

		if slices.Contains(postLogout[:i], uri) {
			return fmt.Errorf("%w: post-logout redirect URI %d is repeated", ErrInvalidClient, i+1)
		}
	}

	if backchannel != "" {
		if err := checkRedirectURI(backchannel); err != nil {
			return fmt.Errorf("%w: back-channel logout URI: %w", ErrInvalidClient, err)
		}
	}

	return nil
}

// SetLogout replaces the logout settings of a client. The policy version is raised by the store with the change.
func (c *Client) SetLogout(postLogout []string, backchannel string, now time.Time) error {
	if err := checkLogoutURIs(postLogout, backchannel); err != nil {
		return err
	}

	c.PostLogoutRedirectURIs, c.BackchannelLogoutURI, c.UpdatedAt = slices.Clone(postLogout), backchannel, now.UTC()

	return nil
}

// AllowsPostLogoutRedirect reports whether uri is registered, compared exactly.
func (c *Client) AllowsPostLogoutRedirect(uri string) bool {
	return slices.Contains(c.PostLogoutRedirectURIs, uri)
}
