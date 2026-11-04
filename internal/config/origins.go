package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

var appleAppID = regexp.MustCompile(`^[A-Z0-9]{10}\.[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*$`)

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

const androidOriginPrefix = "android:apk-key-hash:"

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

func parseAppleAppIDs(list string) ([]string, error) {
	var ids []string

	for item := range strings.SplitSeq(list, ",") {
		id := strings.TrimSpace(item)
		if !appleAppID.MatchString(id) {
			return nil, fmt.Errorf("%q: want TEAMID.bundle.id, such as ABCDE12345.com.example.app", id)
		}

		ids = append(ids, id)
	}

	return ids, nil
}
