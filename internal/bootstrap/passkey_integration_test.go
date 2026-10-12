//go:build integration

package bootstrap_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"airlance.org/auth/internal/testutil"
)

const (
	testRPID     = "example.test"
	testRPOrigin = "https://example.test"
)

func newAuthenticator(t *testing.T) *testutil.SoftAuthenticator {
	t.Helper()
	return testutil.NewSoftAuthenticator(t, testRPID, testRPOrigin)
}

// ceremonyOf extracts the challenge and the options a begin route answered with.
func ceremonyOf(t *testing.T, status int, body map[string]any) (challengeID string, options []byte) {
	t.Helper()
	if status != http.StatusOK {
		t.Fatalf("begin ceremony = %d %v", status, body)
	}
	challengeID, _ = body["challenge_id"].(string)
	options, err := json.Marshal(body["options"])
	if err != nil || challengeID == "" {
		t.Fatalf("ceremony = %v, %v", body, err)
	}
	return challengeID, options
}

// registerPasskey runs the native registration with the ticket of a verify.
func (c client) registerPasskey(auth *testutil.SoftAuthenticator, ticket, binding string, extra map[string]any) (int, map[string]any) {
	c.t.Helper()
	status, begun := c.call(http.MethodPost, "/v1/native/auth/passkey/register/options", map[string]any{
		"ticket": ticket, "client_binding": binding,
	})
	challengeID, options := ceremonyOf(c.t, status, begun)
	body := map[string]any{
		"ticket": ticket, "client_binding": binding, "challenge_id": challengeID,
		"credential": json.RawMessage(auth.Register(options)),
	}
	for k, v := range extra {
		body[k] = v
	}
	return c.call(http.MethodPost, "/v1/native/auth/passkey/register/verify", body)
}

// assertPasskey runs the native passkey login; ticket and binding may be empty.
func (c client) assertPasskey(auth *testutil.SoftAuthenticator, ticket, binding string) (int, map[string]any) {
	c.t.Helper()
	status, begun := c.call(http.MethodPost, "/v1/native/auth/passkey/login/options", nil)
	challengeID, options := ceremonyOf(c.t, status, begun)
	body := map[string]any{"challenge_id": challengeID, "credential": json.RawMessage(auth.Assert(options))}
	if ticket != "" {
		body["ticket"] = ticket
	}
	if binding != "" {
		body["client_binding"] = binding
	}
	return c.call(http.MethodPost, "/v1/native/auth/passkey/login/verify", body)
}

// registerPasskey runs the browser registration; the binding is the page's cookie.
func (p *page) registerPasskey(t *testing.T, auth *testutil.SoftAuthenticator, ticket string) (*http.Response, string) {
	t.Helper()
	resp, body := p.post("/v1/auth/passkey/register/options", mustJSON(t, map[string]any{"ticket": ticket}))
	var begun struct {
		ChallengeID string          `json:"challenge_id"`
		Options     json.RawMessage `json:"options"`
	}
	if err := json.Unmarshal([]byte(body), &begun); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("register options = %d %s", resp.StatusCode, body)
	}
	return p.post("/v1/auth/passkey/register/verify", mustJSON(t, map[string]any{
		"ticket": ticket, "challenge_id": begun.ChallengeID, "credential": json.RawMessage(auth.Register(begun.Options)),
		"device_name": "test page",
	}))
}

// assertPasskey runs the browser passkey login; ticket may be empty.
func (p *page) assertPasskey(t *testing.T, auth *testutil.SoftAuthenticator, ticket string) (*http.Response, string) {
	t.Helper()
	resp, body := p.post("/v1/auth/passkey/login/options", "")
	var begun struct {
		ChallengeID string          `json:"challenge_id"`
		Options     json.RawMessage `json:"options"`
	}
	if err := json.Unmarshal([]byte(body), &begun); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("login options = %d %s", resp.StatusCode, body)
	}
	req := map[string]any{"challenge_id": begun.ChallengeID, "credential": json.RawMessage(auth.Assert(begun.Options))}
	if ticket != "" {
		req["ticket"] = ticket
	}
	return p.post("/v1/auth/passkey/login/verify", mustJSON(t, req))
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
