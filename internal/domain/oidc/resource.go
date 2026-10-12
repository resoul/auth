package oidc

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Resource statuses.
const (
	ResourceActive   = "active"
	ResourceDisabled = "disabled"
)

const (
	maxResourceURILen  = 2048
	maxAudienceLen     = 256
	maxResourceScopes  = 32
	maxRequestedAPIs   = 5
	maxScopeNameLen    = 64
	maxScopeParamLen   = 1024
	maxRequestedScopes = 40
)

// A resource identifier is also an audit value, so it uses only lower-case letters, digits, '-' and '_'.
var resourceIDShape = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,63}$`)

// An API scope is a namespaced right: a lower-case namespace and one to three more parts, as in messages:send or
// video:upload. The colon keeps the whole space apart from the protocol scopes (openid, email), which never have one.
var apiScopeShape = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}(:[a-z0-9_]{1,32}){1,3}$`)

// ParseResourceID validates a resource identifier.
func ParseResourceID(s string) (string, error) {
	if !resourceIDShape.MatchString(s) {
		return "", ErrInvalidResourceID
	}
	return s, nil
}

// ValidAPIScope reports whether s has the shape of an API scope.
func ValidAPIScope(s string) bool { return len(s) <= maxScopeNameLen && apiScopeShape.MatchString(s) }

// Resource is a logical API: the recipient of an access token. It is not an application that signs users in (a Client)
// and its audience is not the client_id of the application that calls it. One resource may stand for several internal
// services with a common boundary of trust, or for a single service; the registration does not tell which.
type Resource struct {
	ID     string
	Name   string
	Status string
	// URI is the value of the resource parameter (RFC 8707) that selects the resource. It identifies; the provider never
	// requests it.
	URI string
	// Audience is the aud of every access token issued for the resource. A token names exactly one.
	Audience string
	// Scopes are the rights the owner of the API defined for it.
	Scopes []string
	// PolicyVersion is raised whenever the resource's rights change.
	PolicyVersion int
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// NewResourceParams are the inputs of NewResource.
type NewResourceParams struct {
	ID       string
	Name     string
	URI      string
	Audience string
	Scopes   []string
}

// NewResource validates a registration.
func NewResource(p NewResourceParams, now time.Time) (*Resource, error) {
	if _, err := ParseResourceID(p.ID); err != nil {
		return nil, err
	}
	if p.Name == "" || len(p.Name) > 100 {
		return nil, fmt.Errorf("%w: a name of 1 to 100 characters is required", ErrInvalidResource)
	}
	if err := CheckResourceURI(p.URI); err != nil {
		return nil, fmt.Errorf("%w: resource URI: %w", ErrInvalidResource, err)
	}
	if err := CheckAudience(p.Audience); err != nil {
		return nil, fmt.Errorf("%w: audience: %w", ErrInvalidResource, err)
	}
	if err := checkCatalog(p.Scopes); err != nil {
		return nil, err
	}
	return &Resource{
		ID: p.ID, Name: p.Name, Status: ResourceActive, URI: p.URI, Audience: p.Audience, Scopes: slices.Clone(p.Scopes),
		PolicyVersion: 1, CreatedAt: now.UTC(), UpdatedAt: now.UTC(),
	}, nil
}

// CheckResourceURI checks the value of the resource parameter: an absolute URI of the same plain kind as a redirect
// URI, and without a query, which would make two spellings of one API.
func CheckResourceURI(raw string) error {
	if len(raw) > maxResourceURILen {
		return fmt.Errorf("longer than %d characters", maxResourceURILen)
	}
	if err := checkRedirectURI(raw); err != nil {
		return err
	}
	if u, err := url.Parse(raw); err != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "?") {
		return fmt.Errorf("must not have a query")
	}
	return nil
}

// CheckAudience checks the aud of a resource: printable ASCII without spaces, quotes or a backslash, of up to 256
// characters. A short name such as platform-api and an https URL are both fine.
func CheckAudience(s string) error {
	if s == "" || len(s) > maxAudienceLen {
		return fmt.Errorf("1 to %d characters are required", maxAudienceLen)
	}
	for _, r := range s {
		if r <= ' ' || r >= 0x7f || r == '"' || r == '\\' || r == '#' {
			return fmt.Errorf("must be printable ASCII without spaces, quotes, backslashes or a fragment")
		}
	}
	return nil
}

// checkCatalog validates the scopes a resource defines: one to 32, each of the API shape, none repeated.
func checkCatalog(scopes []string) error {
	if len(scopes) == 0 || len(scopes) > maxResourceScopes {
		return fmt.Errorf("%w: 1 to %d scopes are required", ErrInvalidResource, maxResourceScopes)
	}
	for i, s := range scopes {
		if !ValidAPIScope(s) || slices.Contains(scopes[:i], s) {
			return fmt.Errorf("%w: scope %q", ErrInvalidScope, s)
		}
	}
	return nil
}

// Active reports whether tokens may be issued for the resource.
func (r *Resource) Active() bool { return r.Status == ResourceActive }

// Defines reports whether scope is one of the resource's own.
func (r *Resource) Defines(scope string) bool { return slices.Contains(r.Scopes, scope) }

// SetScopes replaces the scopes the resource defines and returns the ones taken away; the caller ends the grants that
// hold them. Raising the policy version is the store's part, with the change.
func (r *Resource) SetScopes(scopes []string, now time.Time) (removed []string, err error) {
	if err := checkCatalog(scopes); err != nil {
		return nil, err
	}
	for _, s := range r.Scopes {
		if !slices.Contains(scopes, s) {
			removed = append(removed, s)
		}
	}
	r.Scopes, r.UpdatedAt = slices.Clone(scopes), now.UTC()
	return removed, nil
}

// ClientResource is what one client may ask for from one resource: a subset of the resource's scopes. Without a row a
// client may not ask for the resource at all.
type ClientResource struct {
	ClientID   string
	ResourceID string
	Scopes     []string
}

// CheckPermission validates the scopes allowed to a client against what the resource defines.
func (r *Resource) CheckPermission(scopes []string) error {
	if len(scopes) == 0 || len(scopes) > maxResourceScopes {
		return fmt.Errorf("%w: 1 to %d scopes are required", ErrInvalidScope, maxResourceScopes)
	}
	for i, s := range scopes {
		if !r.Defines(s) || slices.Contains(scopes[:i], s) {
			return fmt.Errorf("%w: scope %q", ErrInvalidScope, s)
		}
	}
	return nil
}

// ResourceScopes are the API scopes agreed for one resource: in an authorization request, a code or a grant.
type ResourceScopes struct {
	ResourceID string
	// PolicyVersion is the version of the resource's policy the scopes were agreed under; it is recorded, not compared.
	PolicyVersion int
	Scopes        []string
}

// FindResource returns the entry of the resource, or nil.
func FindResource(list []ResourceScopes, resourceID string) *ResourceScopes {
	for i := range list {
		if list[i].ResourceID == resourceID {
			return &list[i]
		}
	}
	return nil
}

// CoversResources reports whether granted holds every resource of asked with every scope asked.
func CoversResources(granted, asked []ResourceScopes) bool {
	for _, a := range asked {
		g := FindResource(granted, a.ResourceID)
		if g == nil {
			return false
		}
		for _, s := range a.Scopes {
			if !slices.Contains(g.Scopes, s) {
				return false
			}
		}
	}
	return true
}

// Intersect returns the scopes of a that are also in b, in the order of a.
func Intersect(a, b []string) []string {
	var out []string
	for _, s := range a {
		if slices.Contains(b, s) {
			out = append(out, s)
		}
	}
	return out
}

// ParseResourceURIs checks the resource parameters of an authorization request: up to five, each well formed, none
// repeated. A malformed one is ErrInvalidTarget; whether it names a registered resource is for the store to say.
func ParseResourceURIs(raw []string) ([]string, error) {
	if len(raw) > maxRequestedAPIs {
		return nil, ErrInvalidTarget
	}
	for i, u := range raw {
		if CheckResourceURI(u) != nil || slices.Contains(raw[:i], u) {
			return nil, ErrInvalidTarget
		}
	}
	return raw, nil
}

// ScopeRequest is a scope parameter split into what OpenID Connect defines and the rights of APIs.
type ScopeRequest struct {
	// Protocol are openid and email, in the order asked.
	Protocol []string
	// API are the rights of resources, in the order asked.
	API []string
}

// ParseScopeRequest splits a scope parameter (RFC 6749 section 3.3): scopes separated by single spaces and compared
// as they are, case included. It refuses an empty list, a repeated scope, a scope that is neither a protocol scope
// nor shaped like an API scope, and a list without openid.
func ParseScopeRequest(raw string) (ScopeRequest, error) {
	if raw == "" || len(raw) > maxScopeParamLen || strings.TrimSpace(raw) != raw || strings.Contains(raw, "  ") {
		return ScopeRequest{}, ErrInvalidScope
	}
	list := strings.Split(raw, " ")
	if len(list) > maxRequestedScopes {
		return ScopeRequest{}, ErrInvalidScope
	}
	var out ScopeRequest
	for i, s := range list {
		if slices.Contains(list[:i], s) {
			return ScopeRequest{}, ErrInvalidScope
		}
		switch {
		case slices.Contains(SupportedScopes(), s):
			out.Protocol = append(out.Protocol, s)
		case ValidAPIScope(s):
			out.API = append(out.API, s)
		default:
			return ScopeRequest{}, ErrInvalidScope
		}
	}
	if !slices.Contains(out.Protocol, ScopeOpenID) {
		return ScopeRequest{}, ErrInvalidScope
	}
	return out, nil
}

// ParseAPIScopes parses the scope parameter of a token request for a resource: API scopes only, separated by single
// spaces, none repeated. A protocol scope there is an error: a resource token carries none.
func ParseAPIScopes(raw string) ([]string, error) {
	if raw == "" || len(raw) > maxScopeParamLen || strings.TrimSpace(raw) != raw || strings.Contains(raw, "  ") {
		return nil, ErrInvalidScope
	}
	list := strings.Split(raw, " ")
	if len(list) > maxResourceScopes {
		return nil, ErrInvalidScope
	}
	for i, s := range list {
		if !ValidAPIScope(s) || slices.Contains(list[:i], s) {
			return nil, ErrInvalidScope
		}
	}
	return list, nil
}

// AgreeScopes works out what an authorization request is granted of each requested resource. The rights a client may
// ask of a resource are those it was allowed (perms) that the resource still defines. Every API scope asked must belong
// to at least one of the resources asked, and every resource asked must get at least one: a resource without a right
// is a request that means nothing. The result keeps the order of resources and of scopes as asked.
func AgreeScopes(resources []*Resource, perms map[string][]string, api []string) ([]ResourceScopes, error) {
	if len(resources) == 0 {
		if len(api) > 0 {
			return nil, ErrInvalidScope
		}
		return nil, nil
	}
	if len(api) == 0 {
		return nil, ErrInvalidScope
	}
	out := make([]ResourceScopes, 0, len(resources))
	used := make(map[string]bool, len(api))
	for _, r := range resources {
		allowed, ok := perms[r.ID]
		if !ok {
			return nil, ErrInvalidTarget
		}
		var agreed []string
		for _, s := range api {
			if r.Defines(s) && slices.Contains(allowed, s) {
				agreed = append(agreed, s)
				used[s] = true
			}
		}
		if len(agreed) == 0 {
			return nil, ErrInvalidScope
		}
		out = append(out, ResourceScopes{ResourceID: r.ID, PolicyVersion: r.PolicyVersion, Scopes: agreed})
	}
	for _, s := range api {
		if !used[s] {
			return nil, ErrInvalidScope
		}
	}
	return out, nil
}
