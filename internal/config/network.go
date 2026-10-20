package config

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// privateNetworks never carry a request from the internet straight to the service: a proxy there is the operator's.
var privateNetworks = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("::1/128"),
}

// PublicProxyNetworks returns the trusted proxy networks that reach beyond private addresses. A CDN in front of the
// service belongs there; anything else lets a client on the internet name its own address in X-Forwarded-For, and
// with it escape the limits kept per address.
func PublicProxyNetworks(proxies []netip.Prefix) []netip.Prefix {
	var public []netip.Prefix

	for _, p := range proxies {
		inside := func(r netip.Prefix) bool { return r.Bits() <= p.Bits() && r.Contains(p.Addr()) }
		if !slices.ContainsFunc(privateNetworks, inside) {
			public = append(public, p)
		}
	}

	return public
}

// parseTrustedProxies reads a comma-separated list of CIDRs or single IPs. A network
// covering the whole address space would let any client choose its own address, so it
// is refused. The messages never echo the value.
func parseTrustedProxies(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix

	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil, errors.New("want comma-separated CIDRs such as 10.0.0.0/8 or 127.0.0.1, without empty items")
		}

		p, err := netip.ParsePrefix(item)
		if err != nil {
			a, aerr := netip.ParseAddr(item)
			if aerr != nil {
				return nil, errors.New("want comma-separated CIDRs such as 10.0.0.0/8 or 127.0.0.1")
			}

			p = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
		}

		p = p.Masked()
		if p.Bits() == 0 {
			return nil, errors.New("a network of every address cannot be a trusted proxy")
		}

		out = append(out, p)
	}

	return out, nil
}

// checkListenAddr accepts an IP literal with a port, such as 127.0.0.1:8080, [::1]:8080, 0.0.0.0:8080 or
// [::]:8080. A host name and an empty host (which would mean "every interface" without saying so) are
// refused, and so is a port outside 1-65535.
func checkListenAddr(addr string) error {
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return errors.New("want ip:port such as 127.0.0.1:8080, [::1]:8080 or 0.0.0.0:8080")
	}

	if p, err := strconv.Atoi(portText); err != nil || p < 1 || p > 65535 {
		return errors.New("want a port from 1 to 65535")
	}

	if net.ParseIP(host) == nil {
		return errors.New("want an IP address, not a name or an empty host; write 0.0.0.0 to listen on every interface")
	}

	return nil
}

// ListensBeyondLoopback reports whether the listen address (already checked by checkListenAddr) accepts
// connections from other machines: any address that is not a loopback IP, the wildcards included.
func ListensBeyondLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}

	ip := net.ParseIP(host)

	return ip != nil && !ip.IsLoopback()
}
