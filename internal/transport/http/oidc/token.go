package oidc

import (
	"encoding/json"
	"mime"
	"net/http"
	"net/url"
	"strings"

	appoidc "go.airlance.org/auth/internal/application/oidc"
)

var tokenParams = []string{"grant_type", "code", "redirect_uri", "code_verifier", "refresh_token", "scope"}

func (h *Handler) token(w http.ResponseWriter, r *http.Request) {
	noStore(w)

	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/x-www-form-urlencoded" {
		oauthError(w, http.StatusBadRequest, &appoidc.Failure{Code: appoidc.ErrInvalidRequest, Description: "The body must be application/x-www-form-urlencoded."})
		return
	}

	id, secret, ok := clientCredentials(r)
	if !ok {
		h.clientRefused(w, r)
		return
	}

	if err := r.ParseForm(); err != nil || r.URL.RawQuery != "" {
		oauthError(w, http.StatusBadRequest, &appoidc.Failure{Code: appoidc.ErrInvalidRequest, Description: "The request is not valid."})
		return
	}

	for _, name := range tokenParams {
		if len(r.PostForm[name]) > 1 {
			oauthError(w, http.StatusBadRequest, &appoidc.Failure{Code: appoidc.ErrInvalidRequest, Description: "A parameter was repeated."})
			return
		}
	}

	if len(r.PostForm["resource"]) > 1 {
		h.denied(r, "oidc_token", appoidc.ErrInvalidTarget)
		oauthError(w, http.StatusBadRequest, &appoidc.Failure{Code: appoidc.ErrInvalidTarget, Description: "A token is issued for one resource."})

		return
	}

	got, err := h.d.Token.Execute(r.Context(), appoidc.TokenCommand{
		ClientID: id, ClientSecret: secret, GrantType: r.PostForm.Get("grant_type"), Code: r.PostForm.Get("code"),
		RedirectURI: r.PostForm.Get("redirect_uri"), CodeVerifier: r.PostForm.Get("code_verifier"),
		RefreshToken: r.PostForm.Get("refresh_token"), Scope: r.PostForm.Get("scope"), Resource: r.PostForm.Get("resource"),
	})
	if err != nil {
		h.serverError(w, r, err)
		return
	}

	if got.Failure != nil {
		h.denied(r, "oidc_token", got.Failure.Code)

		if got.Replay {
			h.d.Logger.WarnContext(r.Context(), "request denied", "operation", "oidc_token", "reason", "token_reused")
		}

		if got.Failure.Code == appoidc.ErrInvalidClient {
			h.clientRefused(w, r)
			return
		}

		oauthError(w, http.StatusBadRequest, got.Failure)

		return
	}

	body := map[string]any{
		"access_token": got.Response.AccessToken, "token_type": "Bearer", "expires_in": got.Response.ExpiresIn, "scope": got.Response.Scope,
	}
	if got.Response.RefreshToken != "" {
		body["refresh_token"] = got.Response.RefreshToken
	}

	if got.Response.IDToken != "" {
		body["id_token"] = got.Response.IDToken
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

func clientCredentials(r *http.Request) (id, secret string, ok bool) {
	id, secret, ok = r.BasicAuth()
	if ok {
		id, errID := url.QueryUnescape(id)

		secret, errSecret := url.QueryUnescape(secret)
		if errID != nil || errSecret != nil {
			return "", "", false
		}

		return id, secret, true
	}

	if err := r.ParseForm(); err != nil || len(r.PostForm["client_id"]) != 1 || r.PostForm.Get("client_id") == "" {
		return "", "", false
	}

	return r.PostForm.Get("client_id"), "", true
}

func (h *Handler) clientRefused(w http.ResponseWriter, r *http.Request) {
	h.denied(r, "oidc_token", appoidc.ErrInvalidClient)
	w.Header().Set("WWW-Authenticate", `Basic realm="airlance", charset="UTF-8"`)
	oauthError(w, http.StatusUnauthorized, &appoidc.Failure{Code: appoidc.ErrInvalidClient, Description: "The client could not be authenticated."})
}

func bearer(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t") {
		return "", false
	}

	return token, true
}
