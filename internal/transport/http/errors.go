package http

import (
	"context"
	"encoding/json"
	"net/http"

	"airlance.org/auth/internal/transport/http/openapi"
)

// problem is the error body: a stable public code and the request ID, nothing internal.
func problem(ctx context.Context, code openapi.ErrorCode) openapi.Error {
	return openapi.Error{Code: code, RequestId: requestID(ctx)}
}

// malformedRequest answers a body that is not valid JSON or is too large.
func (a *API) malformedRequest(w http.ResponseWriter, r *http.Request, err error) {
	a.logger.DebugContext(r.Context(), "malformed request", "route", r.Pattern, "error", err)
	writeProblem(w, r, http.StatusBadRequest, openapi.ErrorCodeInvalidRequest)
}

// failedRequest answers a technical failure of a use case. It is the one place that
// logs it; the client sees the same temporary unavailability whatever the input was.
func (a *API) failedRequest(w http.ResponseWriter, r *http.Request, err error) {
	a.logger.ErrorContext(r.Context(), "request failed", "route", r.Pattern, "error", err)
	writeProblem(w, r, http.StatusServiceUnavailable, openapi.ErrorCodeTemporarilyUnavailable)
}

func writeProblem(w http.ResponseWriter, r *http.Request, status int, code openapi.ErrorCode) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(problem(r.Context(), code)) // the client went away; nothing to do
}
