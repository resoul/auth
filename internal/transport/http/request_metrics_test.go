package http_test

import (
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"go.airlance.org/auth/internal/application/port"
	httpapi "go.airlance.org/auth/internal/transport/http"
)

type servedRecord struct {
	route  string
	status int
}

type deniedRecord struct{ operation, reason string }

// recorder keeps what the transport reports, for assertions.
type recorder struct {
	mu     sync.Mutex
	served []servedRecord
	denied []deniedRecord
}

func (r *recorder) RequestServed(route string, status int, _ time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.served = append(r.served, servedRecord{route, status})
}

func (r *recorder) AuthDenied(operation, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.denied = append(r.denied, deniedRecord{operation, reason})
}

func (r *recorder) count(route string, status int) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	n := 0

	for _, s := range r.served {
		if s.route == route && s.status == status {
			n++
		}
	}

	return n
}

func (r *recorder) denials(operation, reason string) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	n := 0

	for _, d := range r.denied {
		if d.operation == operation && d.reason == reason {
			n++
		}
	}

	return n
}

func TestRequestsAndRefusalsAreReportedByRouteAndReason(t *testing.T) {
	rec := &recorder{}
	e := newEnvWith(t, func(d *httpapi.Deps) { d.Requests = rec })

	started := e.start("alice@example.test", "")
	if got := e.verify(started.FlowID, "00000000", started.ClientBinding); got.Code != http.StatusBadRequest {
		t.Fatalf("verify = %d", got.Code)
	}

	e.get("/health/alive")
	e.get("/no/such/route")

	for route, want := range map[string]struct {
		status, n int
	}{
		"POST " + startPath:  {http.StatusAccepted, 1},
		"POST " + verifyPath: {http.StatusBadRequest, 1},
		"GET /health/alive":  {http.StatusOK, 1},
		"unmatched":          {http.StatusNotFound, 1},
	} {
		if got := rec.count(route, want.status); got != want.n {
			t.Errorf("%s %d: counted %d, want %d (all: %+v)", route, want.status, got, want.n, rec.served)
		}
	}

	if got := rec.denials("verify", "wrong_code"); got != 1 {
		t.Errorf("verify/wrong_code denials = %d (all: %+v)", got, rec.denied)
	}
}

func TestTheRecordsCarryNoRequestData(t *testing.T) {
	rec := &recorder{}
	e := newEnvWith(t, func(d *httpapi.Deps) { d.Requests = rec })
	e.start("alice@example.test", "")
	m := nativeManage(t, e, "bob@example.test")
	m.json(http.MethodDelete, "/passkeys/0198a2b4-7c3d-7e5f-8a1b-2c3d4e5f6a7c", "", nil)
	e.get("/v1/sessions?token=secret")

	for _, s := range rec.served {
		for _, forbidden := range []string{"alice", "bob", "0198a2b4", "secret", "@", "?"} {
			if strings.Contains(s.route, forbidden) {
				t.Errorf("route label %q carries %q", s.route, forbidden)
			}
		}
	}

	for _, d := range rec.denied {
		for _, forbidden := range []string{"alice", "bob", "0198a2b4", "@"} {
			if strings.Contains(d.operation, forbidden) || strings.Contains(d.reason, forbidden) {
				t.Errorf("denial %+v carries %q", d, forbidden)
			}
		}
	}
}

func TestAServerFailureIsReportedAsAFiveHundredClass(t *testing.T) {
	rec := &recorder{}
	e := newEnvWith(t, func(d *httpapi.Deps) { d.Requests = rec })
	e.faults.wrap = func(s port.Stores) port.Stores { s.Outbox = failingOutbox{s.Outbox}; return s }

	got := e.post(startPath, map[string]string{"email": "alice@example.test"})
	if got.Code < 500 {
		t.Fatalf("start = %d, want a server failure", got.Code)
	}

	if rec.count("POST "+startPath, got.Code) != 1 {
		t.Errorf("the failure was not reported: %+v", rec.served)
	}
}

func TestTheMetricsScrapeIsNotCountedAsTraffic(t *testing.T) {
	rec := &recorder{}

	e := newEnvWith(t, func(d *httpapi.Deps) { d.Requests = rec })
	if got := e.get("/metrics"); got.Code != http.StatusOK {
		t.Fatalf("/metrics = %d", got.Code)
	}

	if len(rec.served) != 0 {
		t.Errorf("the scrape was counted: %+v", rec.served)
	}
}

func TestWithoutARecorderTheTransportStillAnswers(t *testing.T) {
	e := newEnv(t)
	if got := e.get("/health/alive"); got.Code != http.StatusOK {
		t.Errorf("alive = %d", got.Code)
	}
}
