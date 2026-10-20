package oidc

import (
	"encoding/json"
	"net/http"

	appoidc "go.airlance.org/auth/internal/application/oidc"
)

func (h *Handler) userinfo(w http.ResponseWriter, r *http.Request) {
	noStore(w)

	token, ok := bearer(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", "Bearer")
		oauthError(w, http.StatusUnauthorized, &appoidc.Failure{Code: appoidc.ErrInvalidToken, Description: "A Bearer access token is required."})

		return
	}

	got, err := h.d.UserInfo.Execute(r.Context(), token)
	if err != nil {
		h.serverError(w, r, err)
		return
	}

	if got.Failure != nil {
		h.denied(r, "oidc_userinfo", got.Failure.Code)
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		oauthError(w, http.StatusUnauthorized, got.Failure)

		return
	}

	body := map[string]any{"sub": got.Claims.Subject}
	if got.Claims.HasEmail {
		body["email"], body["email_verified"] = got.Claims.Email, got.Claims.EmailVerified
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}
