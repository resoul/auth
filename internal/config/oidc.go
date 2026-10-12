package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
)

// loadOIDC reads the OpenID Provider settings. The provider needs the HTTP API (it is served from its listener),
// the oidc_signing keys, passkeys (its sign-in page uses them) and the database.
func loadOIDC(lookup LookupFunc, cfg *Config) []error {
	raw := value(lookup, EnvOIDCIssuer)
	if raw == "" {
		return nil
	}
	issuer, err := checkIssuer(raw)
	if err != nil {
		return []error{fmt.Errorf("%s: %w", EnvOIDCIssuer, err)}
	}
	var errs []error
	if !cfg.HTTP.Enabled() {
		errs = append(errs, fmt.Errorf("%s needs %s: the provider is served from the API listener", EnvOIDCIssuer, EnvHTTPAddr))
	}
	if cfg.Keyring == nil || cfg.Keyring.OIDCSigning == nil {
		errs = append(errs, fmt.Errorf("an oidc_signing keyring is required when %s is set: the provider signs ID tokens with RS256", EnvOIDCIssuer))
	}
	if !slices.Contains(cfg.WebAuthn.Origins, issuer) {
		errs = append(errs, fmt.Errorf("%s must be one of %s: the sign-in page runs on the issuer's origin", EnvOIDCIssuer, EnvWebAuthnOrigins))
	}
	if len(errs) > 0 {
		return errs
	}
	cfg.OIDC = OIDCConfig{Issuer: issuer}
	if v := value(lookup, EnvOIDCBackchannelAllow); v != "" {
		nets, err := parseNetworks(v)
		if err != nil {
			return []error{fmt.Errorf("%s: %w", EnvOIDCBackchannelAllow, err)}
		}
		cfg.OIDC.BackchannelAllow = nets
	}
	return nil
}

// parseNetworks reads a comma-separated list of CIDRs or single IPs. A network of every address is refused: it would
// switch the protection it belongs to off. Messages never echo the value.
func parseNetworks(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return nil, errors.New("empty list item")
		}
		p, err := netip.ParsePrefix(item)
		if err != nil {
			a, aerr := netip.ParseAddr(item)
			if aerr != nil {
				return nil, errors.New("want CIDR networks or IP addresses")
			}
			p = netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen())
		}
		p = p.Masked()
		if p.Bits() == 0 {
			return nil, errors.New("a network of every address cannot be allowed")
		}
		out = append(out, p)
	}
	return out, nil
}

// checkIssuer accepts an origin: https, or http for localhost and loopback IPs only, with no path, query, fragment or
// credentials. The issuer is what clients compare against iss, so there is exactly one spelling.
func checkIssuer(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("want an origin such as https://auth.example.com, without a path or trailing slash")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if ip := net.ParseIP(u.Hostname()); u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "", errors.New("an http issuer is allowed for localhost or a loopback IP only")
		}
	default:
		return "", errors.New("want an https origin")
	}
	if u.Host != strings.ToLower(u.Host) {
		return "", errors.New("write the host in lower case")
	}
	return u.Scheme + "://" + u.Host, nil
}
