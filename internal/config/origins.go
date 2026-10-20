package config

import (
	"errors"
	"net"
	"net/url"
	"strings"
)

// checkInvitationURL accepts the address an invitation sends people to: https, or http on the local machine,
// without credentials or a fragment. Messages never echo the value.
func checkInvitationURL(raw string) error {
	u, err := url.Parse(raw)
	if raw == "" || err != nil || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return errors.New("want an address such as https://app.example.com/login")
	}

	switch u.Scheme {
	case "https":
	case "http":
		if ip := net.ParseIP(u.Hostname()); u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return errors.New("an http address is allowed for localhost or a loopback IP only")
		}
	default:
		return errors.New("want an https address")
	}

	return nil
}

// parseBrowserOrigins reads a comma-separated list of exact origins. A wildcard, a path,
// credentials and a plain-HTTP origin outside the local machine are refused: a trusted
// origin may act with the user's cookies. Messages never echo the value.
func parseBrowserOrigins(list string) ([]string, error) {
	var out []string

	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)

		u, err := url.Parse(item)
		if item == "" || err != nil || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil || u.Opaque != "" || u.Hostname() == "" {
			return nil, errors.New("want comma-separated origins such as https://app.example.com, each without a path")
		}

		switch u.Scheme {
		case "https":
		case "http":
			if ip := net.ParseIP(u.Hostname()); u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
				return nil, errors.New("an http origin is allowed for localhost or a loopback IP only")
			}
		default:
			return nil, errors.New("want an https origin")
		}

		if strings.ContainsAny(u.Hostname(), "*") {
			return nil, errors.New("a wildcard origin is not allowed")
		}

		out = append(out, u.Scheme+"://"+strings.ToLower(u.Host))
	}

	return out, nil
}

// validRPID accepts a lower-case domain of letters, digits, hyphens and dots, or localhost.
// An IP address is not a valid relying party ID.
func validRPID(id string) bool {
	if len(id) == 0 || len(id) > 253 || net.ParseIP(id) != nil {
		return false
	}

	for _, label := range strings.Split(id, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}

		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}

	return true
}

// androidOriginPrefix starts the origin of an Android app, which the platform reports as the
// hash of the app's signing key.
const androidOriginPrefix = "android:apk-key-hash:"

// parseWebAuthnOrigins reads the origins of ceremonies: web origins as for the browser
// profile, and the opaque origins of Android apps. Messages never echo the value.
func parseWebAuthnOrigins(list string) ([]string, error) {
	var out []string

	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if rest, ok := strings.CutPrefix(item, androidOriginPrefix); ok {
			if rest == "" || strings.ContainsAny(rest, " /?#") {
				return nil, errors.New("an android origin is android:apk-key-hash: followed by the key hash")
			}

			out = append(out, item)

			continue
		}

		web, err := parseBrowserOrigins(item)
		if err != nil {
			return nil, err
		}

		out = append(out, web...)
	}

	return out, nil
}

// checkOriginsMatchRPID refuses a web origin outside the relying party's domain: the browser
// would never accept a ceremony there, so it is a typo rather than a choice.
func checkOriginsMatchRPID(origins []string, rpID string) error {
	for _, o := range origins {
		if strings.HasPrefix(o, androidOriginPrefix) {
			continue
		}

		u, err := url.Parse(o)
		if err != nil {
			return errors.New("want comma-separated origins")
		}

		host := u.Hostname()
		if host != rpID && !strings.HasSuffix(host, "."+rpID) {
			return errors.New("every web origin must be the relying party ID or one of its subdomains")
		}
	}

	return nil
}
