package oidc

import (
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"strings"

	appoidc "airlance.org/auth/internal/application/oidc"
)

// introspect is the token introspection endpoint (RFC 7662). The caller is an API: it authenticates with the identifier
// and the secret of its resource, in Basic form like a client at the token endpoint, and is told about tokens issued for
// that resource only. Anything else is {"active": false}.
func (h *Handler) introspect(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	refused := func() {
		h.denied(r, "oidc_introspect", appoidc.ErrInvalidClient)
		w.Header().Set("WWW-Authenticate", `Basic realm="airlance", charset="UTF-8"`)
		oauthError(w, http.StatusUnauthorized, &appoidc.Failure{Code: appoidc.ErrInvalidClient, Description: "The resource could not be authenticated."})
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/x-www-form-urlencoded" {
		oauthError(w, http.StatusBadRequest, &appoidc.Failure{Code: appoidc.ErrInvalidRequest, Description: "The body must be application/x-www-form-urlencoded."})
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		refused()
		return
	}
	id, errID := url.QueryUnescape(id)
	secret, errSecret := url.QueryUnescape(secret)
	if errID != nil || errSecret != nil {
		refused()
		return
	}
	if err := r.ParseForm(); err != nil || r.URL.RawQuery != "" || len(r.PostForm["token"]) != 1 || len(r.PostForm.Get("token")) > 4096 {
		oauthError(w, http.StatusBadRequest, &appoidc.Failure{Code: appoidc.ErrInvalidRequest, Description: "Exactly one token is required."})
		return
	}
	got, err := h.d.Introspect.Execute(r.Context(), appoidc.IntrospectCommand{ResourceID: id, Secret: secret, Token: r.PostForm.Get("token")})
	if err != nil {
		h.serverError(w, r, err)
		return
	}
	if got.Failure != nil {
		refused()
		return
	}
	body := map[string]any{"active": false}
	if t := got.Token; t != nil {
		body = map[string]any{
			"active": true, "scope": strings.Join(t.Scope, " "), "client_id": t.ClientID, "sub": t.Subject, "aud": t.Audience,
			"iss": h.d.Issuer, "jti": t.JTI, "iat": t.IssuedAt.Unix(), "exp": t.ExpiresAt.Unix(), "token_type": "Bearer",
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}
