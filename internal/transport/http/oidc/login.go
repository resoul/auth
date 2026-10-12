package oidc

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"

	appoidc "airlance.org/auth/internal/application/oidc"
)

// loginPage serves the page that signs the user in. It is one static file: the request is read from the address by
// the page's script, and nothing from the request is written into the markup.
func (h *Handler) loginPage(w http.ResponseWriter, _ *http.Request) {
	data, err := web.ReadFile("web/login.html")
	if err != nil {
		panic(err) // the file is part of the embed pattern
	}
	pageSecurity(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// completeLogin turns the sign-in the page just made into the shared OP session and the code the client waits for.
// The proof is the access token in the Authorization header, never a cookie, so a page of another site cannot make
// the browser send it; the request id and the cookie of the browser that began tie it to one authorization request.
func (h *Handler) completeLogin(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		oauthError(w, http.StatusBadRequest, &appoidc.Failure{Code: appoidc.ErrInvalidRequest, Description: "The body must be application/json."})
		return
	}
	token, ok := bearer(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", "Bearer")
		oauthError(w, http.StatusUnauthorized, &appoidc.Failure{Code: appoidc.ErrAccessDenied, Description: "A Bearer access token is required."})
		return
	}
	var body struct {
		RequestID string `json:"request_id"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		oauthError(w, http.StatusBadRequest, &appoidc.Failure{Code: appoidc.ErrInvalidRequest, Description: "The request is not valid."})
		return
	}
	got, err := h.d.Login.Execute(r.Context(), appoidc.CompleteLoginCommand{
		RequestSecret: body.RequestID, BindingSecret: cookieValue(r, requestCookie), AccessToken: token,
	})
	if err != nil {
		h.serverError(w, r, err)
		return
	}
	if got.Failure != nil {
		h.denied(r, "oidc_login", got.Failure.Code)
		status := http.StatusBadRequest
		if got.Failure.Code == appoidc.ErrAccessDenied {
			status = http.StatusUnauthorized
		}
		oauthError(w, status, got.Failure)
		return
	}
	if got.SSOSecret != "" {
		h.setCookie(w, ssoCookie, got.SSOSecret, got.SSOExpiresAt.Sub(h.now()))
	}
	// The binding cookie has done its work: the request is spent.
	http.SetCookie(w, &http.Cookie{Name: requestCookie, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"redirect_to": got.Location})
}
