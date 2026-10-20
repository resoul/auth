package oidc

import (
	"slices"
	"strings"
)

// Scopes the provider offers. Profile claims are not stored yet, so there is no profile scope; offline_access is not
// offered either: a refresh token lives only as long as the sign-in it came from.
const (
	ScopeOpenID = "openid"
	ScopeEmail  = "email"
)

// SupportedScopes is the list the discovery document publishes.
func SupportedScopes() []string { return []string{ScopeOpenID, ScopeEmail} }

// ParseScopes splits a space-separated scope parameter. It refuses an empty list, a repeated scope, an unknown one
// and a list without openid: this provider serves OpenID Connect only.
func ParseScopes(raw string) ([]string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.Contains(raw, "  ") {
		return nil, ErrInvalidScope
	}

	scopes := strings.Split(raw, " ")
	for i, s := range scopes {
		if !slices.Contains(SupportedScopes(), s) || slices.Contains(scopes[:i], s) {
			return nil, ErrInvalidScope
		}
	}

	if !slices.Contains(scopes, ScopeOpenID) {
		return nil, ErrInvalidScope
	}

	return scopes, nil
}

// HasScope reports whether the list holds the scope.
func HasScope(scopes []string, scope string) bool { return slices.Contains(scopes, scope) }
