package oidc

import (
	"html/template"
	"net/http"
	"net/url"
	"time"

	appoidc "airlance.org/auth/internal/application/oidc"
	httpapi "airlance.org/auth/internal/transport/http"
)

// authorizeParams are the single-valued parameters of an authorization request.
var authorizeParams = []string{
	"response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method", "prompt", "max_age",
}

// authorize handles GET and POST. A GET reads the query; a POST reads the body only, and a POST that also has a query
// is ambiguous, so it is refused once the redirect URI can be trusted.
func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) {
	var values url.Values
	repeated := false
	if r.Method == http.MethodPost {
		if r.URL.RawQuery != "" {
			repeated = true
		}
		if err := r.ParseForm(); err != nil {
			repeated = true
		}
		values = r.PostForm
	} else {
		values = r.URL.Query()
	}
	for _, name := range authorizeParams {
		if len(values[name]) > 1 {
			repeated = true
		}
	}
	// The resource parameter (RFC 8707) may come more than once; the application counts and checks them. Anything else
	// past the known parameters, such as request or claims, is not supported and not read.
	cmd := appoidc.AuthorizeCommand{
		ResponseType: values.Get("response_type"), ClientID: values.Get("client_id"), RedirectURI: values.Get("redirect_uri"),
		Scope: values.Get("scope"), State: values.Get("state"), Nonce: values.Get("nonce"), CodeChallenge: values.Get("code_challenge"),
		CodeChallengeMethod: values.Get("code_challenge_method"), Prompt: values.Get("prompt"), MaxAge: values.Get("max_age"),
		Resources: values["resource"], Repeated: repeated, SSOSecret: cookieValue(r, ssoCookie), ClientIP: httpapi.ClientIPFromContext(r.Context()),
	}
	got, err := h.d.Authorize.Execute(r.Context(), cmd)
	if err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	noStore(w)
	w.Header().Set("Referrer-Policy", "no-referrer")
	switch got.Kind {
	case appoidc.AuthorizeRedirect:
		status := http.StatusFound
		if r.Method == http.MethodPost {
			status = http.StatusSeeOther
		}
		http.Redirect(w, r, got.Location, status)
	case appoidc.AuthorizeLogin:
		h.setCookie(w, requestCookie, got.BindingSecret, h.d.Policy.RequestTTL)
		http.Redirect(w, r, "/oauth2/login?request="+url.QueryEscape(got.RequestID), http.StatusSeeOther)
	default:
		h.d.Requests.AuthDenied("oidc_authorize", got.Failure.Code)
		h.errorPage(w, http.StatusBadRequest, got.Failure.Description)
	}
}

func cookieValue(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

// setCookie sets a host-only, Secure, HttpOnly, Lax cookie for maxAge.
func (h *Handler) setCookie(w http.ResponseWriter, name, value string, maxAge time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(maxAge / time.Second),
	})
}

// pageSecurity are the headers of every page the provider shows: no framing, no scripts but its own, no leaking of
// the address, no guessing of types.
func pageSecurity(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	noStore(w)
}

var errorTemplate = template.Must(template.New("error").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign-in problem</title><link rel="stylesheet" href="/oauth2/login/app.css"></head>
<body><main><h1>Sign-in problem</h1><p>{{.}}</p><p class="hint">Close this page and start again from the application.</p></main></body></html>
`))

// errorPage shows a fixed message on the provider. The browser is not sent anywhere: the client or its return
// address could not be trusted.
func (h *Handler) errorPage(w http.ResponseWriter, status int, message string) {
	pageSecurity(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = errorTemplate.Execute(w, message)
}

func (h *Handler) serverErrorPage(w http.ResponseWriter, r *http.Request, err error) {
	h.d.Logger.ErrorContext(r.Context(), "oidc request failed", "route", r.Pattern, "error", err)
	h.errorPage(w, http.StatusServiceUnavailable, "The service is temporarily unavailable.")
}
