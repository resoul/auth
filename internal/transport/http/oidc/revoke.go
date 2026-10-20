package oidc

import (
	"mime"
	"net/http"
	"net/url"

	appoidc "go.airlance.org/auth/internal/application/oidc"
)

// revoke is the revocation endpoint (RFC 7009). The client authenticates as at the token endpoint. The answer is an empty
// 200 for any token, so a client cannot learn whether a token it does not own exists.
func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	noStore(w)

	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/x-www-form-urlencoded" {
		oauthError(w, http.StatusBadRequest, &appoidc.Failure{Code: appoidc.ErrInvalidRequest, Description: "The body must be application/x-www-form-urlencoded."})
		return
	}

	id, secret, ok := r.BasicAuth()
	if !ok {
		h.clientRefused(w, r)
		return
	}

	id, errID := url.QueryUnescape(id)

	secret, errSecret := url.QueryUnescape(secret)
	if errID != nil || errSecret != nil {
		h.clientRefused(w, r)
		return
	}

	if err := r.ParseForm(); err != nil || r.URL.RawQuery != "" || len(r.PostForm["token"]) != 1 {
		oauthError(w, http.StatusBadRequest, &appoidc.Failure{Code: appoidc.ErrInvalidRequest, Description: "Exactly one token is required."})
		return
	}

	got, err := h.d.Revoke.Execute(r.Context(), appoidc.RevokeCommand{ClientID: id, ClientSecret: secret, Token: r.PostForm.Get("token")})
	if err != nil {
		h.serverError(w, r, err)
		return
	}

	if got.Failure != nil {
		h.clientRefused(w, r)
		return
	}

	w.WriteHeader(http.StatusOK)
}
