package http_test

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"go.airlance.org/auth/internal/adapter/memory"
	"go.airlance.org/auth/internal/domain/quota"
	httpapi "go.airlance.org/auth/internal/transport/http"
)

func prefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()

	var out []netip.Prefix
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}

	return out
}

func requestFrom(remote string, xff ...string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, startPath, nil)

	r.RemoteAddr = remote
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}

	return r
}

func TestClientIP(t *testing.T) {
	proxies := prefixes(t, "10.0.0.0/8", "fd00::/8")
	for _, tc := range []struct {
		name    string
		req     *http.Request
		proxies []netip.Prefix
		want    string
	}{
		{"no proxies: the peer", requestFrom("192.0.2.1:5000", "203.0.113.5"), nil, "192.0.2.1"},
		{"peer is not a proxy: the header is ignored", requestFrom("192.0.2.1:5000", "203.0.113.5"), proxies, "192.0.2.1"},
		{"trusted proxy: the forwarded client", requestFrom("10.0.0.2:5000", "203.0.113.5"), proxies, "203.0.113.5"},
		{"the client's own forged entries are left of the real one", requestFrom("10.0.0.2:5000", "1.2.3.4, 203.0.113.5"), proxies, "203.0.113.5"},
		{"a chain of proxies is skipped from the right", requestFrom("10.0.0.2:5000", "203.0.113.5, 10.0.0.9, 10.0.0.7"), proxies, "203.0.113.5"},
		{"several header lines read as one list", requestFrom("10.0.0.2:5000", "1.2.3.4", "203.0.113.5"), proxies, "203.0.113.5"},
		{"no header behind a proxy: the proxy", requestFrom("10.0.0.2:5000"), proxies, "10.0.0.2"},
		{"only proxies listed: the last one", requestFrom("10.0.0.2:5000", "10.0.0.9"), proxies, "10.0.0.9"},
		{"a malformed entry stops the walk at the proxy", requestFrom("10.0.0.2:5000", "203.0.113.5, not-an-ip"), proxies, "10.0.0.2"},
		{"an empty entry is skipped", requestFrom("10.0.0.2:5000", "203.0.113.5, "), proxies, "203.0.113.5"},
		{"an IPv6 peer behind an IPv6 proxy", requestFrom("[fd00::1]:5000", "2001:db8::7"), proxies, "2001:db8::7"},
		{"a mapped IPv4 peer counts as IPv4", requestFrom("[::ffff:10.0.0.2]:5000", "203.0.113.5"), proxies, "203.0.113.5"},
		{"a mapped IPv4 client is IPv4", requestFrom("10.0.0.2:5000", "::ffff:203.0.113.5"), proxies, "203.0.113.5"},
		{"a zone is dropped", requestFrom("10.0.0.2:5000", "fe80::1%eth0"), proxies, "fe80::1"},
		{"an unparsable peer is unknown", requestFrom("garbage"), proxies, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := httpapi.ClientIP(tc.req, tc.proxies)
			if tc.want == "" {
				if got.IsValid() {
					t.Errorf("ClientIP = %v, want unknown", got)
				}

				return
			}

			if got.String() != tc.want {
				t.Errorf("ClientIP = %v, want %s", got, tc.want)
			}
		})
	}
}

func ipBudget(t *testing.T) memory.Option {
	t.Helper()

	p, err := quota.NewProfile(map[quota.Scope][]quota.Window{quota.UnknownSendIP: {{Limit: 1, Per: time.Hour}}})
	if err != nil {
		t.Fatal(err)
	}

	return memory.WithQuota(p)
}

func (e *env) startRequest(email, remote, xff string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, startPath, strings.NewReader(`{"email": "`+email+`"}`))
	req.Header.Set("Content-Type", "application/json")

	req.RemoteAddr = remote
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}

	return e.do(req)
}

func TestTheIPBudgetFollowsTheForwardedClientBehindATrustedProxy(t *testing.T) {
	e := newEnvBehind(t, prefixes(t, "192.0.2.0/24"), ipBudget(t))
	decode[startResponse](t, e.startRequest("a@example.test", "192.0.2.1:1", "203.0.113.5"), http.StatusAccepted)
	wantProblem(t, e.startRequest("b@example.test", "192.0.2.1:2", "203.0.113.5"), http.StatusTooManyRequests, "rate_limited")
	decode[startResponse](t, e.startRequest("b@example.test", "192.0.2.1:3", "203.0.113.6"), http.StatusAccepted)
}

func TestForwardingHeadersAreIgnoredWithoutATrustedProxy(t *testing.T) {
	e := newEnv(t, ipBudget(t))
	decode[startResponse](t, e.startRequest("a@example.test", "192.0.2.1:1", "203.0.113.5"), http.StatusAccepted)
	// Changing the header does not give the client a new budget.
	wantProblem(t, e.startRequest("b@example.test", "192.0.2.1:2", "203.0.113.99"), http.StatusTooManyRequests, "rate_limited")
	// A different peer is a different client.
	decode[startResponse](t, e.startRequest("b@example.test", "198.51.100.1:3", "203.0.113.5"), http.StatusAccepted)
}
