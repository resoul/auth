package config

import (
	"fmt"
	"strings"
)

// loadAdmin reads the admin API settings. Setting any of them without the address is an error, so a
// half-written configuration cannot leave the admin API off unnoticed.
func loadAdmin(lookup LookupFunc, cfg *Config) []error {
	addr, rp, origins := value(lookup, EnvAdminAddr), strings.ToLower(value(lookup, EnvAdminRPID)), value(lookup, EnvAdminOrigins)
	if addr == "" {
		for _, key := range []string{EnvAdminRPID, EnvAdminOrigins} {
			if value(lookup, key) != "" {
				return []error{fmt.Errorf("%s is set without %s", key, EnvAdminAddr)}
			}
		}
		return nil
	}
	var errs []error
	if err := checkListenAddr(addr); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", EnvAdminAddr, err))
	}
	switch {
	case rp == "":
		errs = append(errs, fmt.Errorf("%s is required when %s is set: operators sign in with a passkey", EnvAdminRPID, EnvAdminAddr))
	case !validRPID(rp):
		errs = append(errs, fmt.Errorf("%s: want a domain such as admin.example.com or localhost, without scheme, port or path", EnvAdminRPID))
		rp = ""
	case rp == cfg.WebAuthn.RPID:
		errs = append(errs, fmt.Errorf("%s must differ from %s: an operator's page must not offer a user's passkey", EnvAdminRPID, EnvWebAuthnRPID))
	}
	var list []string
	if origins == "" {
		errs = append(errs, fmt.Errorf("%s is required when %s is set", EnvAdminOrigins, EnvAdminAddr))
	} else if parsed, err := parseBrowserOrigins(origins); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", EnvAdminOrigins, err))
	} else {
		list = parsed
		if rp != "" {
			if err := checkOriginsMatchRPID(list, rp); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", EnvAdminOrigins, err))
			}
		}
	}
	if len(errs) > 0 {
		return errs
	}
	cfg.Admin = AdminConfig{Addr: addr, RPID: rp, Origins: list}
	return nil
}
