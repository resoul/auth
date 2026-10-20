//go:build integration

package bootstrap_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"testing"

	"go.airlance.org/auth/internal/testutil"
)

func (c client) startFrom(email, binding, xff string) (int, map[string]any) {
	c.t.Helper()

	body := map[string]string{"email": email}
	if binding != "" {
		body["client_binding"] = binding
	}

	data, err := json.Marshal(body)
	if err != nil {
		c.t.Fatal(err)
	}

	req, err := http.NewRequest(http.MethodPost, c.base+"/v1/native/auth/email/start", bytes.NewReader(data))
	if err != nil {
		c.t.Fatal(err)
	}

	req.Header.Set("X-Forwarded-For", xff)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}

	defer func() { _ = resp.Body.Close() }()

	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)

	return resp.StatusCode, out
}

// The owner's availability, over the real process:
// unknown clients from many addresses exhaust the budget of the email; the device that
// proved the email still starts and signs in.
func TestTheOwnerSignsInWhileUnknownClientsAreExhausted(t *testing.T) {
	s := newService(t)
	smtp := testutil.NewFakeSMTP(t)
	cfg, base := s.apiConfig(addrOf(smtp))
	cfg.HTTP.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}

	stop := s.start(cfg)
	defer stop()

	c := client{t: t, base: base}
	waitReady(t, base)

	status, started := c.startFrom("alice@example.test", "", "203.0.113.1")
	flowID, _ := started["flow_id"].(string)

	binding, _ := started["client_binding"].(string)
	if status != http.StatusAccepted || flowID == "" || binding == "" {
		t.Fatalf("start = %d %v", status, started)
	}

	waitUntil(t, "the first mail", func() bool { return len(smtp.Messages()) >= 1 })

	m := mailedCode.FindStringSubmatch(smtp.Messages()[0].Data)
	if m == nil {
		t.Fatal("the mail carries no code")
	}

	status, signedIn := c.call(http.MethodPost, "/v1/native/auth/email/verify", map[string]string{
		"flow_id": flowID, "code": m[1] + m[2], "client_binding": binding,
	})
	if status != http.StatusOK {
		t.Fatalf("verify = %d %v", status, signedIn)
	}

	// An attacker, each request from another address, starts flows for the same email.
	limited := 0

	for i := 0; i < 15; i++ {
		status, body := c.startFrom("alice@example.test", "", fmt.Sprintf("198.51.100.%d", i+1))
		if status == http.StatusTooManyRequests {
			if body["code"] != "rate_limited" {
				t.Errorf("429 body = %v", body)
			}

			limited++
		}
	}

	if limited == 0 {
		t.Fatal("the shared budget of unknown clients was never exhausted")
	}

	if status, _ := c.startFrom("alice@example.test", "", "203.0.113.77"); status != http.StatusTooManyRequests {
		t.Fatalf("a new unknown client got through, status %d", status)
	}

	// The owner's device presents its binding and is served from its own budget.
	status, owner := c.startFrom("alice@example.test", binding, "203.0.113.1")
	if status != http.StatusAccepted || owner["flow_id"] == "" {
		t.Fatalf("the owner's start = %d %v", status, owner)
	}

	if n := count(t, s, "quota_events"); n == 0 {
		t.Error("the quota table is empty after the spends")
	}
}

func waitReady(t *testing.T, base string) {
	t.Helper()
	waitUntil(t, "readiness", func() bool {
		resp, err := http.Get(base + "/health/ready")
		if err != nil {
			return false
		}

		_ = resp.Body.Close()

		return resp.StatusCode == http.StatusOK
	})
}
