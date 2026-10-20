package http_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.airlance.org/auth/internal/adapter/jwt"
	"go.airlance.org/auth/internal/testutil"
	httpapi "go.airlance.org/auth/internal/transport/http"
)

func TestJWKSPublishesThePublicKeysThatVerifyAccessTokens(t *testing.T) {
	e := newEnv(t)
	signedIn, _ := e.signIn("alice@example.test")

	rec := e.get("/.well-known/jwks.json")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("status = %d, Content-Type = %q", rec.Code, rec.Header().Get("Content-Type"))
	}

	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Errorf("Cache-Control = %q", got)
	}

	if strings.Contains(rec.Body.String(), `"d"`) {
		t.Fatalf("the key set contains private material: %s", rec.Body)
	}

	keys, err := jwt.ParseJWKS(rec.Body.Bytes())
	if err != nil || len(keys) != 1 || keys["sign-a"] == nil {
		t.Fatalf("keys = %v, %v", keys, err)
	}
	// A product service that knows only the published set accepts the token.
	verifier, err := jwt.NewVerifier(keys, e.clock, issuer, audience, 0)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := verifier.VerifyAccess(signedIn.AccessToken); err != nil {
		t.Errorf("the published keys do not verify the access token: %v", err)
	}
}

func TestHealthRoutes(t *testing.T) {
	e := newEnv(t)
	for _, path := range []string{"/health/alive", "/health/ready"} {
		rec := e.get(path)
		if body := decode[map[string]string](t, rec, http.StatusOK); body["status"] != "ok" {
			t.Errorf("%s = %v", path, body)
		}

		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s may be cached", path)
		}
	}

	e.ready = errors.New("dial tcp 10.0.0.7:5432: connection refused")

	rec := e.get("/health/ready")
	if body := decode[map[string]string](t, rec, http.StatusServiceUnavailable); body["status"] != "unavailable" || len(body) != 1 {
		t.Errorf("ready = %v", body)
	}

	if strings.Contains(rec.Body.String(), "10.0.0.7") {
		t.Error("readiness names the failing dependency")
	}

	if e.get("/health/alive").Code != http.StatusOK {
		t.Error("a dependency failure made the process look dead")
	}
}

func TestMetricsRouteServesTheRegistry(t *testing.T) {
	e := newEnv(t)

	rec := e.get("/metrics")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "airlance_auth_refresh_reuse_total 0") {
		t.Errorf("status = %d, body:\n%s", rec.Code, rec.Body)
	}
}

func TestRoutesKeepTheirMethods(t *testing.T) {
	e := newEnv(t)
	if rec := e.get(startPath); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET start = %d, want 405", rec.Code)
	}

	if rec := e.postRaw("/metrics", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /metrics = %d, want 405", rec.Code)
	}

	if rec := e.get("/v1/auth/email/start"); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET browser start = %d, want 405", rec.Code)
	}

	if rec := e.postRaw("/v1/unknown", "{}"); rec.Code != http.StatusNotFound {
		t.Errorf("an unknown /v1 route = %d, want 404", rec.Code)
	}
}

func TestEveryResponseGetsAFreshRequestID(t *testing.T) {
	e := newEnv(t)
	req := httptest.NewRequest(http.MethodGet, "/health/alive", nil)
	req.Header.Set(httpapi.RequestIDHeader, "forged\nline")
	first := e.do(req).Header().Get(httpapi.RequestIDHeader)

	second := e.get("/health/alive").Header().Get(httpapi.RequestIDHeader)
	if first == "" || first == "forged\nline" || first == second {
		t.Errorf("request ids %q and %q", first, second)
	}
}

func TestLogsCarryNoSecrets(t *testing.T) {
	e := newEnv(t)
	started := e.start("alice@example.test", "")
	code := e.code(started.FlowID)
	e.verify(started.FlowID, "00000000", started.ClientBinding)
	step := decode[nextStepResponse](t, e.verify(started.FlowID, code, started.ClientBinding), http.StatusOK)

	auth := testutil.NewSoftAuthenticator(t, rpID, rpOrigin)
	begun := decode[ceremonyResponse](t, e.post(nativeRegisterOptions, map[string]string{"ticket": step.Ticket, "client_binding": started.ClientBinding}), http.StatusOK)
	credential := auth.Register(begun.Options)
	registered := decode[registerResponse](t, e.post(nativeRegisterVerify, map[string]any{
		"ticket": step.Ticket, "client_binding": started.ClientBinding, "challenge_id": begun.ChallengeID,
		"credential": json.RawMessage(credential),
	}), http.StatusOK)
	// A refused proof and a replayed refresh token end up in the logs too.
	e.post(nativeRegisterVerify, map[string]any{
		"ticket": step.Ticket, "client_binding": started.ClientBinding, "challenge_id": begun.ChallengeID,
		"credential": json.RawMessage(credential),
	})
	rotated := decode[tokenResponse](t, e.refresh(registered.RefreshToken), http.StatusOK)
	e.refresh(registered.RefreshToken)

	logs := e.logs.String()

	secrets := map[string]string{
		"code": code, "binding": started.ClientBinding, "email": "alice@example.test", "flow id": started.FlowID,
		"ticket": step.Ticket, "challenge id": begun.ChallengeID, "credential": string(auth.CredentialID),
		"access token": registered.AccessToken, "refresh token": registered.RefreshToken, "rotated refresh token": rotated.RefreshToken,
	}
	for i, code := range registered.RecoveryCodes {
		secrets[fmt.Sprintf("recovery code %d", i)] = code
	}

	for name, secret := range secrets {
		if strings.Contains(logs, secret) {
			t.Errorf("the logs contain the %s", name)
		}
	}

	if !strings.Contains(logs, `"reason":"wrong_code"`) || !strings.Contains(logs, `"route":"POST /v1/native/auth/email/verify"`) ||
		!strings.Contains(logs, `"reason":"bad_ticket"`) {
		t.Errorf("the logs lack the safe fields:\n%s", logs)
	}
}

func TestNewRequiresDependencies(t *testing.T) {
	if _, err := httpapi.New(httpapi.Deps{Logger: slog.Default(), Ready: func(context.Context) error { return nil }}); err == nil {
		t.Error("New accepted missing use cases")
	}
}
