//go:build integration

package bootstrap_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"go.airlance.org/auth/internal/adapter/clock"
	"go.airlance.org/auth/internal/adapter/jwt"
	"go.airlance.org/auth/internal/bootstrap"
	"go.airlance.org/auth/internal/config"
	"go.airlance.org/auth/internal/testutil"
)

// apiConfig adds the API and a signing key to the mail configuration of the harness.
func (s *service) apiConfig(smtpAddr string) (config.Config, string) {
	s.t.Helper()
	cfg := s.config(smtpAddr)
	cfg.JWT = config.JWTConfig{Issuer: "https://auth.example.test", Audience: "example", AccessTTL: 5 * time.Minute}
	cfg.Keyring.JWTSigning = &config.KeySet{ActiveKID: "sign-a", Keys: map[string]config.KeyRef{
		"sign-a": {KeyFile: testutil.WriteFile(s.t, "sign-a.pem", testutil.NewSigningKeyPEM(s.t).Private)},
	}}
	cfg.HTTP.Addr = freeLoopbackAddr(s.t)
	cfg.WebAuthn = config.WebAuthnConfig{RPID: testRPID, RPName: "Example", Origins: []string{testRPOrigin}}

	return cfg, "http://" + cfg.HTTP.Addr
}

func freeLoopbackAddr(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	addr := ln.Addr().String()
	_ = ln.Close()

	return addr
}

type client struct {
	t    *testing.T
	base string
}

func (c client) call(method, path string, body any) (int, map[string]any) {
	c.t.Helper()

	var reader io.Reader

	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			c.t.Fatal(err)
		}

		reader = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, c.base+path, reader)
	if err != nil {
		c.t.Fatal(err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}

	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatal(err)
	}

	out := map[string]any{"_raw": string(data)}
	_ = json.Unmarshal(data, &out) // /metrics is not JSON

	return resp.StatusCode, out
}

var mailedCode = regexp.MustCompile(`code is (\d{4}) (\d{4})`)

// TestPrototypeDemo exercises one process with
// PostgreSQL, real crypto and JWT; a fake SMTP server stands in for Mailpit.
func TestPrototypeDemo(t *testing.T) {
	s := newService(t)
	smtp := testutil.NewFakeSMTP(t)
	cfg, base := s.apiConfig(addrOf(smtp))

	stop := s.start(cfg)
	defer stop()

	c := client{t: t, base: base}
	waitUntil(t, "readiness", func() bool {
		resp, err := http.Get(base + "/health/ready")
		if err != nil {
			return false
		}

		_ = resp.Body.Close()

		return resp.StatusCode == http.StatusOK
	})

	// 2. Native start for a new email returns the flow and the client binding.
	status, started := c.call(http.MethodPost, "/v1/native/auth/email/start", map[string]string{"email": "alice@example.test"})
	flowID, _ := started["flow_id"].(string)

	binding, _ := started["client_binding"].(string)
	if status != http.StatusAccepted || flowID == "" || binding == "" {
		t.Fatalf("start = %d %v", status, started)
	}

	// 3. The code arrives by mail; verify signs in and creates the session.
	waitUntil(t, "the mail", func() bool { return len(smtp.Messages()) == 1 })

	m := mailedCode.FindStringSubmatch(smtp.Messages()[0].Data)
	if m == nil {
		t.Fatal("the mail carries no code")
	}

	code := m[1] + m[2]
	verify := map[string]string{"flow_id": flowID, "code": code, "client_binding": binding}
	status, proven := c.call(http.MethodPost, "/v1/native/auth/email/verify", verify)

	ticket, _ := proven["ticket"].(string)
	if status != http.StatusOK || proven["next"] != "enroll_passkey" || ticket == "" || proven["access_token"] != nil || proven["refresh_token"] != nil {
		t.Fatalf("verify = %d %v: a proven email is a ticket, not a session", status, proven)
	}

	if n := count(t, s, "sessions"); n != 0 {
		t.Fatalf("%d sessions after verify", n)
	}
	// 3b. A passkey is registered with the ticket; that opens the session.
	auth := newAuthenticator(t)
	status, signedIn := c.registerPasskey(auth, ticket, binding, map[string]any{"device_name": "demo"})
	access, _ := signedIn["access_token"].(string)
	refresh, _ := signedIn["refresh_token"].(string)

	codes, _ := signedIn["recovery_codes"].([]any)
	if status != http.StatusOK || access == "" || refresh == "" || len(codes) != 10 {
		t.Fatalf("register = %d %v", status, signedIn)
	}

	if n := count(t, s, "sessions"); n != 1 {
		t.Errorf("%d sessions after verify", n)
	}

	// The published key set verifies the access token, as a product service would.
	_, jwks := c.call(http.MethodGet, "/.well-known/jwks.json", nil)

	keys, err := jwt.ParseJWKS([]byte(jwks["_raw"].(string)))
	if err != nil {
		t.Fatal(err)
	}

	verifier, err := jwt.NewVerifier(keys, clock.System{}, cfg.JWT.Issuer, cfg.JWT.Audience, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}

	claims, err := verifier.VerifyAccess(access)
	if err != nil || claims.UserID.String() != signedIn["user"].(map[string]any)["id"] {
		t.Errorf("claims = %+v, %v", claims, err)
	}

	// 4. Refresh gives a new pair; the old refresh token is no longer usable.
	status, rotated := c.call(http.MethodPost, "/v1/native/token/refresh", map[string]string{"refresh_token": refresh})
	if status != http.StatusOK || rotated["refresh_token"] == refresh || rotated["refresh_token"] == "" {
		t.Fatalf("refresh = %d %v", status, rotated)
	}

	if status, body := c.call(http.MethodPost, "/v1/native/token/refresh", map[string]string{"refresh_token": refresh}); status != http.StatusUnauthorized || body["code"] != "invalid_refresh" {
		t.Errorf("old refresh = %d %v", status, body)
	}

	// 5. The same flow does not sign in twice.
	if status, body := c.call(http.MethodPost, "/v1/native/auth/email/verify", verify); status != http.StatusBadRequest || body["code"] != "invalid_code" {
		t.Errorf("second verify = %d %v", status, body)
	}

	if n := count(t, s, "sessions"); n != 1 {
		t.Errorf("%d sessions after the second verify", n)
	}

	if n := count(t, s, "auth_tickets"); n != 1 {
		t.Errorf("%d tickets: the flow verified once", n)
	}

	// 6. The passkey alone signs in again, from a client that has no binding, and the email
	// code of a user with a passkey asks for the second factor instead of opening a session.
	status, again := c.assertPasskey(auth, "", "")
	if status != http.StatusOK || again["refresh_token"] == "" || again["client_binding"] == nil {
		t.Fatalf("passkey sign-in = %d %v", status, again)
	}

	if n := count(t, s, "sessions"); n != 2 {
		t.Errorf("%d sessions after the passkey sign-in, want 2", n)
	}

	_, metrics := c.call(http.MethodGet, "/metrics", nil)
	for _, want := range []string{
		`airlance_auth_mail_jobs_total{outcome="sent",quota_class="unknown"} 1`,
		`airlance_auth_refresh_reuse_total 1`,
		`airlance_auth_mail_queue_stats_up 1`,
	} {
		if !strings.Contains(metrics["_raw"].(string), want) {
			t.Errorf("metrics lack %s", want)
		}
	}
}

func TestServiceRefusesToStartTheAPIOnABusyPort(t *testing.T) {
	s := newService(t)
	cfg, _ := s.apiConfig(addrOf(testutil.NewFakeSMTP(t)))

	busy, err := net.Listen("tcp", cfg.HTTP.Addr)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = busy.Close() }()

	err = runOnce(t, cfg)
	if err == nil || !strings.Contains(err.Error(), "http api") {
		t.Fatalf("Run = %v, want a listen failure", err)
	}
}

// runOnce runs the service for at most a few seconds and returns its error.
func runOnce(t *testing.T, cfg config.Config) error {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	return bootstrap.Run(ctx, cfg, bootstrap.NewLogger(io.Discard, cfg.Log))
}

func count(t *testing.T, s *service, table string) int {
	t.Helper()

	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatal(err)
	}

	return n
}

// A separate metrics listener serves /metrics itself and takes the route off the API port.
func TestMetricsListenerReplacesTheAPIRoute(t *testing.T) {
	s := newService(t)
	cfg, base := s.apiConfig(addrOf(testutil.NewFakeSMTP(t)))
	cfg.Metrics.Addr = freeLoopbackAddr(t)

	stop := s.start(cfg)
	defer stop()

	waitUntil(t, "metrics listener", func() bool {
		resp, err := http.Get("http://" + cfg.Metrics.Addr + "/metrics")
		if err != nil {
			return false
		}

		_ = resp.Body.Close()

		return resp.StatusCode == http.StatusOK
	})

	_, scraped := client{t: t, base: "http://" + cfg.Metrics.Addr}.call(http.MethodGet, "/metrics", nil)
	if !strings.Contains(scraped["_raw"].(string), "airlance_auth_mail_queue_stats_up 1") {
		t.Errorf("metrics listener body lacks the queue gauge")
	}

	if status, _ := (client{t: t, base: base}).call(http.MethodGet, "/metrics", nil); status != http.StatusNotFound {
		t.Errorf("API port /metrics = %d, want 404", status)
	}

	if status, _ := (client{t: t, base: "http://" + cfg.Metrics.Addr}).call(http.MethodGet, "/v1/me", nil); status != http.StatusNotFound {
		t.Errorf("metrics port /v1/me = %d, want 404", status)
	}
}

func TestServiceRefusesToStartOnABusyMetricsPort(t *testing.T) {
	s := newService(t)
	cfg, _ := s.apiConfig(addrOf(testutil.NewFakeSMTP(t)))
	cfg.Metrics.Addr = freeLoopbackAddr(t)

	busy, err := net.Listen("tcp", cfg.Metrics.Addr)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = busy.Close() }()

	if err := runOnce(t, cfg); err == nil || !strings.Contains(err.Error(), "metrics") {
		t.Fatalf("Run = %v, want a metrics listen failure", err)
	}
}
