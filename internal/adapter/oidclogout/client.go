// Package oidclogout delivers back-channel logout notices: the server-to-server call that tells a client's backend that a
// person's sign-in ended. The address it calls was registered by an operator but still belongs to someone else's server, so
// the call is made with care: it cannot reach the provider's own network unless that was allowed, it follows no redirect
// and it reads almost nothing back.
package oidclogout

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// errBlocked reports a connection refused before it was made, because the address is not one the provider may call.
var errBlocked = errors.New("address is not allowed for back-channel logout")

// neverCall are the networks a notice may not be sent to unless the operator allowed them: the host itself, private and
// link-local ranges (the cloud metadata address included), carrier-grade NAT, benchmarking and documentation blocks, and
// the multicast and unspecified addresses. The check is on the address the connection is really made to, after DNS, so a name
// that resolves to one of them, or changes its answer between the check and the call, gets nowhere.
var neverCall = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "64:ff9b::/96", "100::/64", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
)

func mustPrefixes(list ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// allowed reports whether a connection to ip may be made: it is not in a network that is never called, or the operator
// listed a network that holds it. An IPv4-mapped IPv6 address counts as the IPv4 address.
func allowed(ip netip.Addr, allow []netip.Prefix) bool {
	ip = ip.Unmap().WithZone("")
	for _, p := range allow {
		if p.Contains(ip) {
			return true
		}
	}
	for _, p := range neverCall {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

// NewHTTPClient returns the client notices are sent with. allow lists the networks the operator permits although they are
// internal, such as the network of the application's backends.
func NewHTTPClient(allow []netip.Prefix, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout: timeout,
		// Control runs for the address a connection is about to be made to, once per attempt, after name resolution.
		Control: func(_, address string, _ syscall.RawConn) error {
			addrPort, err := netip.ParseAddrPort(address)
			if err != nil || !allowed(addrPort.Addr(), allow) {
				return errBlocked
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 nil, // an environment proxy would be a way around the check above
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   timeout,
			ResponseHeaderTimeout: timeout,
			DisableKeepAlives:     true,
		},
		// A redirect is another address nobody vetted; the notice is not delivered there.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
