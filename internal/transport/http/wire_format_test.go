package http_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"airlance.org/auth/internal/testutil"
)

// rawTimes returns the time fields of a response exactly as they are written on the wire.
func rawTimes(t *testing.T, rec *httptest.ResponseRecorder, status int, fields ...string) map[string]string {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, status, rec.Body)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, f := range fields {
		s, ok := body[f].(string)
		if !ok {
			t.Fatalf("response has no string field %q: %s", f, rec.Body)
		}
		out[f] = s
	}
	return out
}

// Every instant the API returns is in UTC, whatever the time zone of the server:
// clients compare and cache these strings, and a mix of +03:00 and Z would be a trap.
func TestTimesOnTheWireAreUTCWhateverTheServerZone(t *testing.T) {
	previous := time.Local
	time.Local = time.FixedZone("EEST", 3*60*60)
	t.Cleanup(func() { time.Local = previous })

	e := newEnv(t)
	start := e.post(startPath, map[string]string{"email": "alice@example.test"})
	started := decode[startResponse](t, start, http.StatusAccepted)
	e.clock.Advance(time.Minute)
	verified := e.verify(started.FlowID, e.code(started.FlowID), started.ClientBinding)
	step := decode[nextStepResponse](t, verified, http.StatusOK)
	e.clock.Advance(time.Minute)
	registered := e.register(testutil.NewSoftAuthenticator(t, rpID, rpOrigin), step.Ticket, started.ClientBinding)
	tokens := decode[tokenResponse](t, registered, http.StatusOK)
	e.clock.Advance(time.Minute)
	refreshed := e.refresh(tokens.RefreshToken)

	checks := map[string]map[string]string{
		"start":    rawTimes(t, start, http.StatusAccepted, "expires_at", "resend_after"),
		"verify":   rawTimes(t, verified, http.StatusOK, "expires_at"),
		"register": rawTimes(t, registered, http.StatusOK, "expires_at"),
		"refresh":  rawTimes(t, refreshed, http.StatusOK, "expires_at"),
	}
	for route, fields := range checks {
		for name, value := range fields {
			if !strings.HasSuffix(value, "Z") {
				t.Errorf("%s %s = %q, want UTC (a trailing Z)", route, name, value)
			}
		}
	}
}
