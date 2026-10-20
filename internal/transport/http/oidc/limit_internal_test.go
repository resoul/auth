package oidc

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func limitedHandler(slots int) *Handler {
	h := &Handler{
		d:        Deps{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Requests: discardRequests{}},
		slotWait: 50 * time.Millisecond,
	}
	if slots > 0 {
		h.slots = make(chan struct{}, slots)
	}

	return h
}

func TestClientRequestsBeyondTheCapAreTurnedAway(t *testing.T) {
	h := limitedHandler(1)

	entered, release := make(chan struct{}), make(chan struct{})
	busy := h.limited(func(w http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		w.WriteHeader(http.StatusOK)
	})

	first := httptest.NewRecorder()
	done := make(chan struct{})

	go func() {
		defer close(done)

		busy(first, httptest.NewRequest(http.MethodPost, "/oauth2/token", nil))
	}()

	<-entered

	// The only slot is taken: the next request waits slotWait, then is refused before it reaches the endpoint.
	reached := false
	second := httptest.NewRecorder()
	h.limited(func(http.ResponseWriter, *http.Request) { reached = true })(second, httptest.NewRequest(http.MethodPost, "/oauth2/token", nil))

	if reached {
		t.Error("a request beyond the cap reached the endpoint")
	}

	var body map[string]string
	if err := json.Unmarshal(second.Body.Bytes(), &body); err != nil {
		t.Fatalf("refusal body %q: %v", second.Body.String(), err)
	}

	if second.Code != http.StatusServiceUnavailable || second.Header().Get("Retry-After") != "1" ||
		second.Header().Get("Cache-Control") != "no-store" || body["error"] != "server_error" {
		t.Errorf("refusal = %d %v %v", second.Code, second.Header(), body)
	}

	// Once the first request ends, its slot serves the next one.
	close(release)
	<-done

	if first.Code != http.StatusOK {
		t.Errorf("first request = %d", first.Code)
	}

	third := httptest.NewRecorder()
	h.limited(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })(third, httptest.NewRequest(http.MethodPost, "/oauth2/token", nil))

	if third.Code != http.StatusNoContent {
		t.Errorf("a request after the slot was freed = %d", third.Code)
	}
}

func TestNoCapServesEveryClientRequest(t *testing.T) {
	h := limitedHandler(0)

	reached := false

	h.limited(func(http.ResponseWriter, *http.Request) { reached = true })(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/oauth2/revoke", nil))

	if !reached {
		t.Error("without a cap the request did not reach the endpoint")
	}
}
