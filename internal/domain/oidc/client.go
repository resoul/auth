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

var clientIDShape = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,63}$`)

var (
	privateScheme = regexp.MustCompile(`^[a-z][a-z0-9+.-]*$`)
	sharedSchemes = []string{"http", "https", "ws", "wss", "ftp", "file", "data", "blob", "about", "javascript", "vbscript", "mailto", "tel", "sms"}
)

const (
	ClientActive   = "active"
	ClientDisabled = "disabled"
)

const (
	maxRedirects   = 10
	maxRedirectLen = 2048
)

const (
	ClientApplication = "application"
	ClientService     = "service"
	ClientNative      = "native"
)

type Client struct {
	ID                     string
	Name                   string
	Kind                   string
	Status                 string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	BackchannelLogoutURI   string
	AllowedScopes          []string
	Trusted                bool
	PolicyVersion          int
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

func ParseClientID(s string) (string, error) {
	if !clientIDShape.MatchString(s) {
		return "", ErrInvalidClientID
	}

	return s, nil
}

type NewClientParams struct {
	ID                     string
	Name                   string
	RedirectURIs           []string
	AllowedScopes          []string
	Trusted                bool
	PostLogoutRedirectURIs []string
	BackchannelLogoutURI   string
	Service                bool
	Native                 bool
}

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

	if p.Service && p.Native {
		return nil, fmt.Errorf("%w: a client is a service or a native application, not both", ErrInvalidClient)
	}

	if p.Native && (len(p.PostLogoutRedirectURIs) > 0 || p.BackchannelLogoutURI != "") {
		return nil, fmt.Errorf("%w: a native application has no logout settings", ErrInvalidClient)
	}

	if !p.Trusted {
		return nil, fmt.Errorf("%w: consent for third-party clients is not implemented; only trusted (first-party) clients can be registered", ErrInvalidClient)
	}

	if len(p.RedirectURIs) == 0 || len(p.RedirectURIs) > maxRedirects {
		return nil, fmt.Errorf("%w: 1 to %d redirect URIs are required", ErrInvalidClient, maxRedirects)
	}

	checkRedirect, kind := checkRedirectURI, ClientApplication
	if p.Native {
		checkRedirect, kind = checkNativeRedirectURI, ClientNative
	}

	for i, uri := range p.RedirectURIs {
		if err := checkRedirect(uri); err != nil {
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
		ID: p.ID, Name: p.Name, Kind: kind, Status: ClientActive, RedirectURIs: slices.Clone(p.RedirectURIs),
		AllowedScopes: slices.Clone(scopes), Trusted: p.Trusted, PolicyVersion: 1,
		PostLogoutRedirectURIs: slices.Clone(p.PostLogoutRedirectURIs), BackchannelLogoutURI: p.BackchannelLogoutURI, CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
	}, nil
}

func parseExactURI(raw string) (*url.URL, error) {
	if raw == "" || len(raw) > maxRedirectLen || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "*\\\r\n\t ") {
		return nil, fmt.Errorf("not a plain absolute URL")
	}

	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" || u.Opaque != "" {
		return nil, fmt.Errorf("not an absolute URL")
	}

	if u.User != nil {
		return nil, fmt.Errorf("must not carry credentials")
	}

	if u.Fragment != "" || strings.Contains(raw, "#") {
		return nil, fmt.Errorf("must not have a fragment")
	}

	return u, nil
}

func checkNativeRedirectURI(raw string) error {
	u, err := parseExactURI(raw)
	if err != nil {
		return err
	}

	scheme, _, _ := strings.Cut(raw, ":")
	if !privateScheme.MatchString(scheme) || slices.Contains(sharedSchemes, u.Scheme) {
		return fmt.Errorf("must use the app's own scheme")
	}

	return nil
}

func checkRedirectURI(raw string) error {
	u, err := parseExactURI(raw)
	if err != nil {
		return err
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

func (c *Client) Active() bool {
	return c.Status == ClientActive
}

func (c *Client) Native() bool {
	return c.Kind == ClientNative
}

func (c *Client) Service() bool {
	return c.Kind == ClientService
}

func (c *Client) AllowsRedirect(uri string) bool {
	return slices.Contains(c.RedirectURIs, uri)
}

func (c *Client) Grantable(requested []string) ([]string, error) {
	for _, s := range requested {
		if !slices.Contains(c.AllowedScopes, s) {
			return nil, ErrInvalidScope
		}
	}

	return requested, nil
}

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

func (c *Client) SetLogout(postLogout []string, backchannel string, now time.Time) error {
	if err := checkLogoutURIs(postLogout, backchannel); err != nil {
		return err
	}

	c.PostLogoutRedirectURIs, c.BackchannelLogoutURI, c.UpdatedAt = slices.Clone(postLogout), backchannel, now.UTC()

	return nil
}

func (c *Client) AllowsPostLogoutRedirect(uri string) bool {
	return slices.Contains(c.PostLogoutRedirectURIs, uri)
}
