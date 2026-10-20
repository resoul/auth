package http

import (
	"context"
	"crypto/rand"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"go.airlance.org/auth/internal/application/port"
)

// RequestIDHeader carries the ID that error bodies and logs also show.
const RequestIDHeader = "X-Request-Id"

type requestIDKey struct{}

// withRequestID gives every request a fresh random ID. An ID sent by the client is
// ignored: it would let a caller forge or collide entries in our logs.
func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := rand.Text()
		w.Header().Set(RequestIDHeader, id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}

func requestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// noStore forbids caching of API and health responses; credential responses must
// never be stored. The key set sets its own policy.
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/") || strings.HasPrefix(r.URL.Path, "/health/") {
			w.Header().Set("Cache-Control", "no-store")
		}

		next.ServeHTTP(w, r)
	})
}

// logRequests writes one line per request with the matched route pattern, never the
// raw path, query, headers or body.
func logRequests(logger *slog.Logger, requests port.RequestMetrics, mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		began := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		mux.ServeHTTP(rec, r)

		route := r.Pattern // set by the mux on this request
		if route == "" {
			route = "unmatched"
		}

		if route != "GET /metrics" { // the scrape is not traffic to alert on
			requests.RequestServed(route, rec.status, time.Since(began))
		}

		logger.InfoContext(r.Context(), "http request",
			"route", route, "status", rec.status,
			"duration_ms", time.Since(began).Milliseconds(),
		)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// WithRequestID, RequestID and LogRequests are the middleware the admin listener shares with this one,
// so both listeners number and log requests the same way.
func WithRequestID(next http.Handler) http.Handler { return withRequestID(next) }

// RequestID returns the ID WithRequestID gave the request.
func RequestID(ctx context.Context) string { return requestID(ctx) }

// LogRequests writes one line per request with the matched route pattern and records it.
func LogRequests(logger *slog.Logger, requests port.RequestMetrics, mux *http.ServeMux) http.Handler {
	return logRequests(logger, requests, mux)
}
