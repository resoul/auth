//go:build integration

package bootstrap_test

import (
	"net/http"
	"strings"
	"testing"
)

// The sign-in page completes the request with the request id and the proof of the person. Anything else is refused on
// the wire, and every refusal leaves the request for the genuine completion, which then works exactly once.
func TestCompletingASignInOnTheWireAcceptsOnlyTheRightProof(t *testing.T) {
	o := newOIDCService(t)
	secret := o.register(t, "panels-web", panelsReturn)
	a := newApp(t, "panels-web", secret, panelsReturn)
	b := newBrowser(t, o.base)

	id := o.proveTo(t, b, a.authorizeURL(nil), "alice@example.test")
	proof := o.lastAccess
	good := `{"request_id": "` + id + `"}`
	complete := func(contentType, body, bearer string) (*http.Response, string) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, o.base+"/oauth2/login/complete", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		return b.do(req)
	}

	// No token: 401, and the answer names the scheme.
	resp, out := complete("application/json", good, "")
	if resp.StatusCode != http.StatusUnauthorized || resp.Header.Get("WWW-Authenticate") != "Bearer" || !strings.Contains(out, "access_denied") {
		t.Errorf("no token = %d %q %s", resp.StatusCode, resp.Header.Get("WWW-Authenticate"), out)
	}
	// Anything but JSON, a field the page does not send, and a body that is not JSON: 400.
	if resp, out = complete("text/plain", good, proof); resp.StatusCode != http.StatusBadRequest || !strings.Contains(out, "invalid_request") {
		t.Errorf("a text body = %d %s", resp.StatusCode, out)
	}
	if resp, out = complete("application/json", `{"request_id": "`+id+`", "remember": true}`, proof); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("an unknown field = %d %s", resp.StatusCode, out)
	}
	if resp, out = complete("application/json", `{"request_id": `, proof); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("a truncated body = %d %s", resp.StatusCode, out)
	}
	// A token that does not verify: 401, as for no token.
	if resp, out = complete("application/json", good, "a.b.c"); resp.StatusCode != http.StatusUnauthorized || !strings.Contains(out, "access_denied") {
		t.Errorf("a forged token = %d %s", resp.StatusCode, out)
	}

	// None of the refusals spent the request: the genuine completion works, and only once.
	resp, out = complete("application/json", good, proof)
	if resp.StatusCode != http.StatusOK || !strings.Contains(out, "code=") {
		t.Fatalf("the genuine completion = %d %s", resp.StatusCode, out)
	}
	if resp, out = complete("application/json", good, proof); resp.StatusCode != http.StatusBadRequest || !strings.Contains(out, "invalid_request") {
		t.Errorf("a second completion = %d %s", resp.StatusCode, out)
	}
}
