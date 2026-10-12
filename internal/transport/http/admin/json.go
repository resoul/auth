package admin

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	appadmin "airlance.org/auth/internal/application/admin"
	httpapi "airlance.org/auth/internal/transport/http"
)

type errorBody struct {
	Error     string `json:"error"`
	Message   string `json:"message,omitempty"`
	RequestID string `json:"request_id,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) // a failed write is the client's gone; nothing to do
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	writeJSON(w, status, errorBody{Error: code, Message: message, RequestID: httpapi.RequestID(r.Context())})
}

// decode reads one JSON object into v, refusing unknown fields, a second value and another content type.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type", "send application/json")
		return false
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, r, http.StatusRequestEntityTooLarge, "too_large", "")
			return false
		}
		writeError(w, r, http.StatusBadRequest, "invalid_request", "the body is not the JSON this endpoint takes")
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "the body holds more than one JSON value")
		return false
	}
	return true
}

// fail answers an error of a use call. A bad input is the operator's to fix; anything else is ours.
func (h *handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, appadmin.ErrInvalidInput) {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	h.Logger.ErrorContext(r.Context(), "admin request failed", "error", err)
	writeError(w, r, http.StatusInternalServerError, "internal", "")
}

// outcome answers every outcome that is not OK; it reports whether it answered.
func (h *handler) outcome(w http.ResponseWriter, r *http.Request, operation string, o appadmin.Outcome, reason appadmin.Reason) bool {
	switch o {
	case appadmin.OutcomeOK:
		return false
	case appadmin.OutcomeUnauthenticated:
		http.SetCookie(w, h.clearedCookie())
		writeError(w, r, http.StatusUnauthorized, "unauthenticated", "")
	case appadmin.OutcomeReauthRequired:
		writeError(w, r, http.StatusForbidden, "reauth_required", "sign in again to do this")
	case appadmin.OutcomeNotFound:
		writeError(w, r, http.StatusNotFound, "not_found", "")
	case appadmin.OutcomeRateLimited:
		h.denied(operation, reason)
		w.Header().Set("Retry-After", "3600")
		writeError(w, r, http.StatusTooManyRequests, "rate_limited", "")
	case appadmin.OutcomeConflict:
		code := "conflict"
		if reason != "" {
			code = string(reason)
		}
		writeError(w, r, http.StatusConflict, code, "")
	case appadmin.OutcomeDenied:
		// Every refusal of a sign-in or an enrollment looks the same; the reason goes to the metrics only.
		h.denied(operation, reason)
		writeError(w, r, http.StatusUnauthorized, "refused", "")
	default:
		h.Logger.ErrorContext(r.Context(), "admin request: unexpected outcome", "outcome", string(o))
		writeError(w, r, http.StatusInternalServerError, "internal", "")
	}
	return true
}

// timeOrNil formats a time, or returns nil for the zero time.
func timeOrNil(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}
