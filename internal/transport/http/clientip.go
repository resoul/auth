package http

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

type clientIPKey struct{}

// withClientIP resolves the client address once per request and hands it to the
// handlers through the context. Forwarding headers count only when the TCP peer is a
// configured proxy.
func withClientIP(trusted []netip.Prefix, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ClientIP(r, trusted)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), clientIPKey{}, ip)))
	})
}

// clientIP returns the address withClientIP resolved; the zero Addr is unknown.
func clientIP(ctx context.Context) netip.Addr {
	ip, _ := ctx.Value(clientIPKey{}).(netip.Addr)
	return ip
}

// ClientIPFromContext returns the address withClientIP resolved for the request, for the handlers that live outside this
// package; the zero Addr is unknown.
func ClientIPFromContext(ctx context.Context) netip.Addr { return clientIP(ctx) }

// ClientIP returns the address of the client. Without trusted proxies, or when the TCP
// peer is not one of them, it is the peer itself and every header is ignored. Behind a
// trusted proxy it is the first address from the right of X-Forwarded-For that is not a
// trusted proxy: entries further left are written by the client and prove nothing. A
// malformed entry stops the walk and the last proxy that spoke is used, so a forged
// header can only make a client share its proxy's budget, never gain a new one.
func ClientIP(r *http.Request, trusted []netip.Prefix) netip.Addr {
	peer := parseAddr(r.RemoteAddr)
	if !peer.IsValid() || !isTrusted(peer, trusted) {
		return peer
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	hop := peer
	for i := len(hops) - 1; i >= 0; i-- {
		entry := strings.TrimSpace(hops[i])
		if entry == "" {
			continue
		}
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return hop
		}
		addr = addr.Unmap().WithZone("")
		if !isTrusted(addr, trusted) {
			return addr
		}
		hop = addr
	}
	return hop
}

func parseAddr(hostport string) netip.Addr {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		host = hostport
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap().WithZone("")
}

func isTrusted(a netip.Addr, trusted []netip.Prefix) bool {
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
