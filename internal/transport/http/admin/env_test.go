package admin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"go.airlance.org/auth/internal/adapter/crypto"
	"go.airlance.org/auth/internal/adapter/memory"
	apasskey "go.airlance.org/auth/internal/adapter/passkey"
	appadmin "go.airlance.org/auth/internal/application/admin"
	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/testutil"
	adminhttp "go.airlance.org/auth/internal/transport/http/admin"
)

const rpID = "localhost"

var t0 = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

// metrics records what the transport reports.
type metrics struct {
	mu     sync.Mutex
	denied []string
	routes []string
}

func (m *metrics) RequestServed(route string, _ int, _ time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.routes = append(m.routes, route)
}

func (m *metrics) AuthDenied(operation, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.denied = append(m.denied, operation+"/"+reason)
}

type env struct {
	t       *testing.T
	store   *memory.Store
	clock   *testutil.FakeClock
	factory *testutil.Factory
	server  *httptest.Server
	origin  string
	client  *http.Client
	metrics *metrics

	operators *appadmin.Operators
	users     *appadmin.Users
	deps      adminhttp.Deps

	// csrf is the token of the signed-in session of the client; send adds it to every request that changes something.
	csrf string
}

func newEnv(t *testing.T) *env {
	return newEnvScheme(t, "http")
}

// newEnvScheme builds the stack for a page served from the scheme. The test server itself speaks plain http;
// the scheme decides the origin the handler trusts and the relying party expects.
func newEnvScheme(t *testing.T, scheme string) *env {
	t.Helper()
	factory := testutil.NewFactory(t, t0)
	e := &env{t: t, store: memory.NewStore(), clock: factory.Clock, factory: factory, metrics: &metrics{}}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	_, portNumber, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	// The listener is on the loopback address; the page and its Origin are localhost, which WebAuthn accepts over http.
	e.origin = scheme + "://localhost:" + portNumber

	web, err := apasskey.New(apasskey.Config{RPID: rpID, RPName: "Admin", Origins: []string{e.origin}})
	if err != nil {
		t.Fatal(err)
	}

	auth, err := appadmin.NewAuth(appadmin.AuthDeps{UnitOfWork: e.store, Clock: e.clock, WebAuthn: web, PasskeyIDs: factory.IDs, Secrets: crypto.Ticket{}})
	must(t, err)
	e.users, err = appadmin.NewUsers(appadmin.UsersDeps{UnitOfWork: e.store, Clock: e.clock})
	must(t, err)
	invitations, err := appadmin.NewInvitations(appadmin.InvitationsDeps{UnitOfWork: e.store, Clock: e.clock})
	must(t, err)
	audit, err := appadmin.NewAudit(appadmin.AuditDeps{UnitOfWork: e.store, Clock: e.clock})
	must(t, err)
	e.operators, err = appadmin.NewOperators(appadmin.OperatorsDeps{
		UnitOfWork: e.store, Clock: e.clock, OperatorIDs: factory.IDs, PasskeyIDs: factory.IDs, Secrets: crypto.Ticket{},
	})
	must(t, err)

	e.deps = adminhttp.Deps{
		Auth: auth, Users: e.users, Invitations: invitations, Audit: audit,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Requests: e.metrics, Origins: []string{e.origin},
	}
	handler, err := adminhttp.New(e.deps)
	must(t, err)

	e.server = httptest.NewUnstartedServer(handler)
	_ = e.server.Listener.Close() // replaced by ln below
	e.server.Listener = ln
	e.server.Start()
	t.Cleanup(e.server.Close)

	jar, err := cookiejar.New(nil)
	must(t, err)

	e.client = &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	return e
}

func must(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatal(err)
	}
}

// reply is a decoded response.
type reply struct {
	status int
	header http.Header
	body   []byte
}

func (r reply) json(t *testing.T, v any) {
	t.Helper()

	if err := json.Unmarshal(r.body, v); err != nil {
		t.Fatalf("decode %q: %v", r.body, err)
	}
}

// errorCode returns the error code of an error reply, or "".
func (r reply) errorCode() string {
	var b struct {
		Error string `json:"error"`
	}

	_ = json.Unmarshal(r.body, &b)

	return b.Error
}

type request struct {
	method, path string
	body         any
	// header overrides: a nil value deletes the header.
	header map[string]*string
	// noOrigin and noContentType drop what a normal page sends.
	raw string
}

func str(s string) *string {
	return &s
}

// send performs a request the way the admin page does: JSON, the page's origin and the CSRF token.
func (e *env) send(r request) reply {
	e.t.Helper()

	var body io.Reader
	switch {
	case r.raw != "":
		body = strings.NewReader(r.raw)
	case r.body != nil:
		data, err := json.Marshal(r.body)
		must(e.t, err)

		body = bytes.NewReader(data)
	}

	req, err := http.NewRequest(r.method, e.server.URL+r.path, body)
	must(e.t, err)

	if r.method != http.MethodGet {
		req.Header.Set("Origin", e.origin)
		req.Header.Set("Content-Type", "application/json")

		if token := e.csrf; token != "" {
			req.Header.Set("X-CSRF-Token", token)
		}
	}

	for k, v := range r.header {
		if v == nil {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, *v)
		}
	}

	resp, err := e.client.Do(req)
	must(e.t, err)

	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	must(e.t, err)

	return reply{status: resp.StatusCode, header: resp.Header, body: data}
}

func (e *env) get(path string) reply {
	return e.send(request{method: http.MethodGet, path: path})
}

func (e *env) post(path string, body any) reply {
	return e.send(request{method: http.MethodPost, path: path, body: body})
}

func (e *env) user(email string) *identity.User {
	e.t.Helper()
	u := e.factory.User(testutil.UserSpec{Email: email})
	must(e.t, e.store.Do(context.Background(), func(ctx context.Context, s port.Stores) error {
		_, _, err := s.Users.Ensure(ctx, u)
		return err
	}))

	return u
}

// enrolled creates an operator on the server side, as the command line does, and registers a key through the API.
func (e *env) enrolled(email string) *testutil.SoftAuthenticator {
	e.t.Helper()
	_, enrollment, err := e.operators.Create(context.Background(), email)
	must(e.t, err)
	key := testutil.NewSoftAuthenticator(e.t, rpID, e.origin)

	begin := e.post("/admin/api/v1/enroll/begin", map[string]string{"code": enrollment.Code})
	if begin.status != http.StatusOK {
		e.t.Fatalf("enroll/begin = %d %s", begin.status, begin.body)
	}

	var ceremony struct {
		ChallengeID string          `json:"challenge_id"`
		Options     json.RawMessage `json:"options"`
	}
	begin.json(e.t, &ceremony)

	done := e.post("/admin/api/v1/enroll/finish", map[string]any{
		"challenge_id": ceremony.ChallengeID, "response": json.RawMessage(key.Register(ceremony.Options)), "name": "Test key",
	})
	if done.status != http.StatusNoContent {
		e.t.Fatalf("enroll/finish = %d %s", done.status, done.body)
	}

	return key
}

// login answers a sign-in with the key and returns the reply of login/finish.
func (e *env) login(key *testutil.SoftAuthenticator) reply {
	e.t.Helper()

	begin := e.post("/admin/api/v1/login/begin", nil)
	if begin.status != http.StatusOK {
		e.t.Fatalf("login/begin = %d %s", begin.status, begin.body)
	}

	var ceremony struct {
		ChallengeID string          `json:"challenge_id"`
		Options     json.RawMessage `json:"options"`
	}
	begin.json(e.t, &ceremony)

	return e.post("/admin/api/v1/login/finish", map[string]any{
		"challenge_id": ceremony.ChallengeID, "response": json.RawMessage(key.Assert(ceremony.Options)),
	})
}

// signedIn enrolls an operator, signs them in and remembers the CSRF token.
func (e *env) signedIn(email string) *testutil.SoftAuthenticator {
	e.t.Helper()
	key := e.enrolled(email)

	res := e.login(key)
	if res.status != http.StatusOK {
		e.t.Fatalf("login/finish = %d %s", res.status, res.body)
	}

	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	res.json(e.t, &body)
	e.csrf = body.CSRFToken

	return key
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()

	u, err := url.Parse(raw)
	must(t, err)

	return u
}
