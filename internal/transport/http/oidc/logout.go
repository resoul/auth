package oidc

import (
	"html/template"
	"net/http"
	"net/url"

	appoidc "airlance.org/auth/internal/application/oidc"
)

// logoutParams are the single-valued parameters of RP-initiated logout.
var logoutParams = []string{"id_token_hint", "client_id", "post_logout_redirect_uri", "state"}

var confirmTemplate = template.Must(template.New("confirm").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign out</title><link rel="stylesheet" href="/oauth2/login/app.css"></head>
<body><main><h1>Sign out?</h1>
<p>You will be signed out of every application you opened with this sign-in.</p>
<form method="post" action="/oauth2/logout">
<input type="hidden" name="confirm" value="{{.Token}}">
{{range .Fields}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">
{{end}}<button type="submit">Sign out</button>
</form></main></body></html>
`))

var signedOutTemplate = template.Must(template.New("signedout").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Signed out</title><link rel="stylesheet" href="/oauth2/login/app.css"></head>
<body><main><h1>Signed out</h1><p>{{.Message}}</p>
{{if .Location}}<p><a href="{{.Location}}">Return to application</a></p>{{end}}
</main></body></html>
`))

type field struct{ Name, Value string }

// logout handles GET (a client's redirect, or a link) and POST (the confirmation of the page below). A GET never changes
// anything; a POST changes something only when it carries the confirmation, and a POST from another site is refused before
// it gets here.
func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	var values url.Values
	repeated := false
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil || r.URL.RawQuery != "" {
			repeated = true
		}
		values = r.PostForm
	} else {
		values = r.URL.Query()
	}
	for _, name := range logoutParams {
		if len(values[name]) > 1 {
			repeated = true
		}
	}
	if len(values["confirm"]) > 1 {
		repeated = true
	}
	if repeated {
		h.errorPage(w, http.StatusBadRequest, "The request is not valid.")
		return
	}
	cmd := appoidc.LogoutCommand{
		IDTokenHint: values.Get("id_token_hint"), ClientID: values.Get("client_id"),
		PostLogoutRedirectURI: values.Get("post_logout_redirect_uri"), State: values.Get("state"),
		SSOSecret: cookieValue(r, ssoCookie), Confirm: r.Method == http.MethodPost, ConfirmToken: values.Get("confirm"),
	}
	got, err := h.d.Logout.Execute(r.Context(), cmd)
	if err != nil {
		h.serverErrorPage(w, r, err)
		return
	}
	switch got.Kind {
	case appoidc.LogoutFailure:
		h.d.Requests.AuthDenied("oidc_logout", got.Failure.Code)
		h.errorPage(w, http.StatusBadRequest, got.Failure.Description)
	case appoidc.LogoutConfirm:
		pageSecurity(w)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		var fields []field
		for _, name := range logoutParams {
			if v := values.Get(name); v != "" {
				fields = append(fields, field{name, v})
			}
		}
		_ = confirmTemplate.Execute(w, struct {
			Token  string
			Fields []field
		}{got.ConfirmToken, fields})
	default:
		// The cookie goes whether or not a sign-in was found: the browser is signed out either way.
		http.SetCookie(w, &http.Cookie{Name: ssoCookie, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
		pageSecurity(w)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		message := "You are not signed in here."
		if got.SignedOut {
			message = "You are signed out of every application you opened with this sign-in."
		}
		// A form POST followed by a cross-origin redirect is blocked by form-action 'self'.
		// Render the result first: its ordinary link can navigate to the validated return address.
		_ = signedOutTemplate.Execute(w, struct {
			Message  string
			Location string
		}{message, got.Location})
	}
}
