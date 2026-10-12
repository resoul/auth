package admin

import (
	"encoding/json"
	"net/http"
	"time"

	appadmin "airlance.org/auth/internal/application/admin"
	"airlance.org/auth/internal/domain/operator"
)

type ceremonyBody struct {
	ChallengeID string          `json:"challenge_id"`
	Options     json.RawMessage `json:"options"`
}

func (h *handler) ceremony(w http.ResponseWriter, r *http.Request, operation string, res appadmin.CeremonyResult) {
	if h.outcome(w, r, operation, res.Outcome, res.Reason) {
		return
	}
	writeJSON(w, http.StatusOK, ceremonyBody{ChallengeID: res.ChallengeID, Options: res.Options})
}

// refuseOrigin answers a request from a page that is not ours. It reports whether it answered.
func (h *handler) refuseOrigin(w http.ResponseWriter, r *http.Request) bool {
	if h.sameOrigin(r) {
		return false
	}
	writeError(w, r, http.StatusForbidden, "bad_origin", "")
	return true
}

func (h *handler) beginEnroll(w http.ResponseWriter, r *http.Request) {
	if h.refuseOrigin(w, r) {
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &body) {
		return
	}
	res, err := h.Auth.BeginEnroll(r.Context(), appadmin.BeginEnrollCommand{Code: body.Code, ClientIP: h.clientIP(r)})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.ceremony(w, r, "enroll_begin", res)
}

func (h *handler) finishEnroll(w http.ResponseWriter, r *http.Request) {
	if h.refuseOrigin(w, r) {
		return
	}
	var body struct {
		ChallengeID string          `json:"challenge_id"`
		Response    json.RawMessage `json:"response"`
		Name        string          `json:"name"`
	}
	if !decode(w, r, &body) {
		return
	}
	res, err := h.Auth.FinishEnroll(r.Context(), appadmin.FinishEnrollCommand{
		ChallengeID: body.ChallengeID, Response: body.Response, Name: body.Name, ClientIP: h.clientIP(r),
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if h.outcome(w, r, "enroll_finish", res.Outcome, res.Reason) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) beginLogin(w http.ResponseWriter, r *http.Request) {
	if h.refuseOrigin(w, r) {
		return
	}
	res, err := h.Auth.BeginLogin(r.Context(), appadmin.BeginLoginCommand{ClientIP: h.clientIP(r)})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.ceremony(w, r, "login_begin", res)
}

type operatorBody struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type sessionBody struct {
	Operator  operatorBody `json:"operator"`
	CSRFToken string       `json:"csrf_token"`
	ExpiresAt time.Time    `json:"expires_at"`
}

func (h *handler) finishLogin(w http.ResponseWriter, r *http.Request) {
	if h.refuseOrigin(w, r) {
		return
	}
	var body struct {
		ChallengeID string          `json:"challenge_id"`
		Response    json.RawMessage `json:"response"`
	}
	if !decode(w, r, &body) {
		return
	}
	res, err := h.Auth.FinishLogin(r.Context(), appadmin.FinishLoginCommand{
		ChallengeID: body.ChallengeID, Response: body.Response, ClientIP: h.clientIP(r),
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if h.outcome(w, r, "login_finish", res.Outcome, res.Reason) {
		return
	}
	http.SetCookie(w, h.sessionCookie(res.SessionSecret))
	writeJSON(w, http.StatusOK, sessionBody{
		Operator:  operatorBody{ID: res.Operator.ID().String(), Email: res.Operator.Email().String()},
		CSRFToken: operator.CSRFToken(res.SessionSecret), ExpiresAt: res.ExpiresAt.UTC(),
	})
}

// principal is a signed-in operator as the transport knows it.
type principal struct {
	actor appadmin.Actor
	auth  appadmin.AuthenticateResult
}

// authed wraps a handler that needs a signed-in operator. A request that changes anything must also come
// from an allowed origin and carry the CSRF token of the session.
func (h *handler) authed(next func(w http.ResponseWriter, r *http.Request, p principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		mutating := r.Method != http.MethodGet && r.Method != http.MethodHead
		if mutating && h.refuseOrigin(w, r) {
			return
		}
		cookie, err := r.Cookie(CookieName)
		if err != nil {
			writeError(w, r, http.StatusUnauthorized, "unauthenticated", "")
			return
		}
		res, err := h.Auth.Authenticate(r.Context(), cookie.Value)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		if h.outcome(w, r, "session", res.Outcome, "") {
			return
		}
		if mutating && !csrfEqual(r.Header.Get(CSRFHeader), res.CSRFToken) {
			writeError(w, r, http.StatusForbidden, "bad_csrf", "")
			return
		}
		next(w, r, principal{actor: res.Actor, auth: res})
	}
}

func (h *handler) session(w http.ResponseWriter, r *http.Request, p principal) {
	writeJSON(w, http.StatusOK, sessionBody{
		Operator:  operatorBody{ID: p.auth.Operator.ID().String(), Email: p.auth.Operator.Email().String()},
		CSRFToken: p.auth.CSRFToken, ExpiresAt: p.auth.ExpiresAt.UTC(),
	})
}

func (h *handler) logout(w http.ResponseWriter, r *http.Request, p principal) {
	if err := h.Auth.Logout(r.Context(), p.actor); err != nil {
		h.fail(w, r, err)
		return
	}
	http.SetCookie(w, h.clearedCookie())
	w.WriteHeader(http.StatusNoContent)
}
