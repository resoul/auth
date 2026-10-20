package admin

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	appadmin "go.airlance.org/auth/internal/application/admin"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/operator"
	httpapi "go.airlance.org/auth/internal/transport/http"
)

// Names and limits of the admin transport.
const (
	// CookieName is the session cookie. Its path is the admin prefix, so it never travels to the public API.
	CookieName = "px_admin"
	cookiePath = "/admin"
	// CSRFHeader carries the token that GET /session and the sign-in response hand out.
	CSRFHeader = "X-CSRF-Token"
	apiPrefix  = "/admin/api/v1"
	// maxBodyBytes bounds a request: the largest is a WebAuthn response of a few kilobytes.
	maxBodyBytes = 64 << 10
)

// Deps are what the admin handlers need.
type Deps struct {
	Auth        *appadmin.Auth
	Users       *appadmin.Users
	Invitations *appadmin.Invitations
	Audit       *appadmin.Audit

	Logger   *slog.Logger
	Requests port.RequestMetrics
	// TrustedProxies are the proxies whose X-Forwarded-For counts, as for the public API.
	TrustedProxies []netip.Prefix
	// Origins are the exact origins of the pages that may call the API. A request that changes anything
	// must come from one of them.
	Origins []string
	// UI serves the admin page below /admin/; nil serves none.
	UI http.Handler
}

type handler struct {
	Deps
	origins map[string]bool
	secure  bool
}

type discardRequests struct{}

func (discardRequests) RequestServed(string, int, time.Duration) {}
func (discardRequests) AuthDenied(string, string)                {}

// New assembles the routes and the middleware.
func New(d Deps) (http.Handler, error) {
	if d.Auth == nil || d.Users == nil || d.Invitations == nil || d.Audit == nil || d.Logger == nil {
		return nil, errors.New("new admin api: all dependencies are required")
	}

	if len(d.Origins) == 0 {
		return nil, errors.New("new admin api: at least one origin is required")
	}

	if d.Requests == nil {
		d.Requests = discardRequests{}
	}

	h := &handler{Deps: d, origins: map[string]bool{}, secure: true}
	for _, o := range d.Origins {
		u, err := url.Parse(o)
		if err != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return nil, fmt.Errorf("new admin api: %q is not an origin", o)
		}

		h.origins[o] = true
		if u.Scheme == "http" {
			// Only localhost may be plain http (config checks it); its cookie cannot be Secure.
			h.secure = false
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST "+apiPrefix+"/enroll/begin", h.beginEnroll)
	mux.HandleFunc("POST "+apiPrefix+"/enroll/finish", h.finishEnroll)
	mux.HandleFunc("POST "+apiPrefix+"/login/begin", h.beginLogin)
	mux.HandleFunc("POST "+apiPrefix+"/login/finish", h.finishLogin)
	mux.HandleFunc("POST "+apiPrefix+"/logout", h.authed(h.logout))
	mux.HandleFunc("GET "+apiPrefix+"/session", h.authed(h.session))
	mux.HandleFunc("GET "+apiPrefix+"/users", h.authed(h.listUsers))
	mux.HandleFunc("GET "+apiPrefix+"/users/{id}", h.authed(h.getUser))
	mux.HandleFunc("POST "+apiPrefix+"/users/{id}/block", h.authed(h.blockUser))
	mux.HandleFunc("POST "+apiPrefix+"/users/{id}/unblock", h.authed(h.unblockUser))
	mux.HandleFunc("POST "+apiPrefix+"/users/{id}/revoke-sessions", h.authed(h.revokeSessions))
	mux.HandleFunc("POST "+apiPrefix+"/users/{id}/delete", h.authed(h.deleteUser))
	mux.HandleFunc("GET "+apiPrefix+"/invitations", h.authed(h.listInvitations))
	mux.HandleFunc("POST "+apiPrefix+"/invitations", h.authed(h.createInvitation))
	mux.HandleFunc("POST "+apiPrefix+"/invitations/revoke", h.authed(h.revokeInvitation))
	mux.HandleFunc("GET "+apiPrefix+"/audit", h.authed(h.listAudit))

	if d.UI != nil {
		// Exactly the page and its assets: a broader pattern would answer an unknown API path with the page.
		mux.Handle("GET /admin/{$}", d.UI)
		mux.Handle("GET /admin/index.html", d.UI)
		mux.Handle("GET /admin/assets/", d.UI)
		mux.Handle("GET /admin", http.RedirectHandler("/admin/", http.StatusMovedPermanently))
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { writeError(w, r, http.StatusNotFound, "not_found", "") })

	return httpapi.WithRequestID(h.baseline(httpapi.LogRequests(d.Logger, d.Requests, mux))), nil
}

// baseline gives every response the headers that keep the API out of caches and frames, and bounds the body.
func (h *handler) baseline(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("X-Frame-Options", "DENY")

		if len(r.URL.Path) >= len(apiPrefix) && r.URL.Path[:len(apiPrefix)] == apiPrefix {
			hd.Set("Cache-Control", "no-store")
			hd.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// sameOrigin reports whether the request carries an allowed Origin. A browser sends Origin on every
// POST, so a missing one is not a browser page of ours.
func (h *handler) sameOrigin(r *http.Request) bool {
	return h.origins[r.Header.Get("Origin")]
}

func csrfEqual(got, want string) bool {
	return len(got) == len(want) && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func (h *handler) sessionCookie(secret string) *http.Cookie {
	return &http.Cookie{
		Name: CookieName, Value: secret, Path: cookiePath, HttpOnly: true, Secure: h.secure,
		SameSite: http.SameSiteStrictMode, MaxAge: int(operator.MaxAge / time.Second),
	}
}

func (h *handler) clearedCookie() *http.Cookie {
	c := h.sessionCookie("")
	c.MaxAge = -1

	return c
}

func (h *handler) clientIP(r *http.Request) netip.Addr { return httpapi.ClientIP(r, h.TrustedProxies) }

// denied counts an expected refusal for the alerts, with the reason of the use case.
func (h *handler) denied(operation string, reason appadmin.Reason) {
	h.Requests.AuthDenied("admin_"+operation, string(reason))
}
