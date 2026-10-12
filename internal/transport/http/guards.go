package http

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
)

// isBrowserRoute tells the browser profile from the native one and the public routes:
// only /v1/ outside /v1/native/ is called by pages with cookies.
func isBrowserRoute(path string) bool {
	return strings.HasPrefix(path, "/v1/") && !strings.HasPrefix(path, "/v1/native/")
}

// withCORS answers the configured origins on the browser profile and nobody else. A
// response to a credentialed request never uses a wildcard origin. The native routes get
// no CORS headers at all: a page cannot call them, and a preflight to them is refused by
// the mux as an unknown method.
func withCORS(allowed []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" || !isBrowserRoute(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Add("Vary", "Origin")
		trusted := slices.Contains(allowed, origin)
		if trusted {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			w.Header().Add("Vary", "Access-Control-Request-Method")
			w.Header().Add("Vary", "Access-Control-Request-Headers")
			if trusted {
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Step-Up")
				w.Header().Set("Access-Control-Max-Age", "600")
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// crossOrigin refuses state-changing requests from origins that are not the API's own or
// trusted. There is no exception for any route. A request with neither Origin nor
// Sec-Fetch-Site is let through, as the standard library does: such a client is not a
// browser page, and SameSite stays the second line for the browsers that omit both.
func (a *API) crossOrigin(trusted, bypass []string, next http.Handler) (http.Handler, error) {
	cop := http.NewCrossOriginProtection()
	for _, origin := range trusted {
		if err := cop.AddTrustedOrigin(origin); err != nil {
			return nil, fmt.Errorf("trusted origin %q: %w", origin, err)
		}
	}
	for _, pattern := range bypass {
		cop.AddInsecureBypassPattern(pattern)
	}
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.logger.DebugContext(r.Context(), "cross-origin request refused", "route", r.URL.Path)
		writeProblem(w, r, http.StatusForbidden, "permission_denied")
	}))
	return cop.Handler(next), nil
}
