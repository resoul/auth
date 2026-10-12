package oidclogout

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestWhichAddressesMayBeCalled(t *testing.T) {
	for _, ip := range []string{"93.184.216.34", "8.8.8.8", "1.1.1.1", "2606:2800:220:1:248:1893:25c8:1946", "172.32.0.1", "11.0.0.1"} {
		if !allowed(netip.MustParseAddr(ip), nil) {
			t.Errorf("%s is a public address and was refused", ip)
		}
	}
	for _, ip := range []string{
		"127.0.0.1", "127.1.2.3", "::1", "0.0.0.0", "::", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "169.254.169.254", "169.254.0.1",
		"100.64.0.1", "100.127.255.255", "198.18.0.1", "224.0.0.1", "239.1.1.1", "255.255.255.255", "240.0.0.1", "fc00::1", "fd12:3456::1", "fe80::1",
		"ff02::1", "64:ff9b::7f00:1", "2001:db8::1",
		// An IPv4 address written as IPv6 is the IPv4 address.
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254",
	} {
		if allowed(netip.MustParseAddr(ip), nil) {
			t.Errorf("%s is an internal address and was allowed", ip)
		}
	}
}

func TestTheOperatorCanAllowANetwork(t *testing.T) {
	allow := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("fd00:1::/32")}
	for ip, want := range map[string]bool{
		"10.20.1.1": true, "10.20.255.255": true, "::ffff:10.20.1.1": true, "fd00:1::5": true,
		"10.21.0.1": false, "10.0.0.1": false, "127.0.0.1": false, "169.254.169.254": false, "fd00:2::1": false,
	} {
		if got := allowed(netip.MustParseAddr(ip), allow); got != want {
			t.Errorf("%s with the allowed networks = %v, want %v", ip, got, want)
		}
	}
}

func TestTheClientDoesNotConnectToInternalAddresses(t *testing.T) {
	client := NewHTTPClient(nil, 2*time.Second)
	hit := make(chan struct{}, 1)
	local := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit <- struct{}{} }))
	t.Cleanup(local.Close)

	for name, target := range map[string]string{
		"the loopback address": local.URL,
		"a name for it":        "http://localhost:" + portOf(t, local.URL) + "/",
		"the metadata address": "http://169.254.169.254/latest/meta-data/",
		"a private address":    "http://10.0.0.1/",
		"an IPv6 loopback":     "http://[::1]:9/",
	} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, target, nil)
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			t.Errorf("%s: the call was made", name)
			continue
		}
		if !errors.Is(err, errBlocked) {
			t.Errorf("%s: the call failed for another reason, so the check did not run: %v", name, err)
		}
	}
	select {
	case <-hit:
		t.Error("the local server was reached")
	default:
	}
}

func TestAnAllowedNetworkIsReachedAndARedirectIsNotFollowed(t *testing.T) {
	second := make(chan struct{}, 1)
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { second <- struct{}{} }))
	t.Cleanup(target.Close)
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	t.Cleanup(redirect.Close)

	client := NewHTTPClient([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, 2*time.Second)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, redirect.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want the redirect itself", resp.StatusCode)
	}
	select {
	case <-second:
		t.Error("the redirect was followed")
	default:
	}
}

func TestEnvironmentProxiesAreIgnored(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	if tr := NewHTTPClient(nil, time.Second).Transport.(*http.Transport); tr.Proxy != nil {
		t.Error("the client honours proxy settings of the environment, which would carry the call around the address check")
	}
}

func portOf(t *testing.T, rawURL string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(rawURL[len("http://"):])
	if err != nil {
		t.Fatal(err)
	}
	return port
}
