package config

import (
	"fmt"
	"net"
	"net/mail"
	"strconv"
	"strings"
)

// loadSMTP reads the mail settings. It checks their shape only; messages never echo values.
func loadSMTP(lookup LookupFunc, smtp *SMTPConfig) []error {
	addr := value(lookup, EnvSMTPAddr)
	if addr == "" {
		for _, key := range []string{EnvSMTPUsername, EnvSMTPPassword, EnvMailFrom, EnvMailFromName} {
			if value(lookup, key) != "" {
				return []error{fmt.Errorf("%s is set without %s", key, EnvSMTPAddr)}
			}
		}
		return nil
	}
	var errs []error
	host, portText, err := net.SplitHostPort(addr)
	portNumber, convErr := strconv.Atoi(portText)
	if err != nil || host == "" || convErr != nil || portNumber < 1 || portNumber > 65535 {
		errs = append(errs, fmt.Errorf("%s: want host:port", EnvSMTPAddr))
	} else {
		smtp.Host, smtp.Port = host, portNumber
	}

	if v := value(lookup, EnvSMTPTLS); v != "" {
		switch v {
		case SMTPTLSNone, SMTPTLSStartTLS, SMTPTLSImplicit:
			smtp.TLS = v
		default:
			errs = append(errs, fmt.Errorf("%s: want none, starttls or tls", EnvSMTPTLS))
		}
	}
	username, password := value(lookup, EnvSMTPUsername), value(lookup, EnvSMTPPassword)
	switch {
	case (username == "") != (password == ""):
		errs = append(errs, fmt.Errorf("%s and %s go together", EnvSMTPUsername, EnvSMTPPassword))
	case username != "" && smtp.TLS == SMTPTLSNone:
		errs = append(errs, fmt.Errorf("%s: credentials are not sent without TLS", EnvSMTPTLS))
	default:
		smtp.Username, smtp.Password = username, NewSecret(password)
	}

	from := strings.TrimSpace(value(lookup, EnvMailFrom))
	if parsed, err := mail.ParseAddress(from); err != nil || parsed.Address != from || parsed.Name != "" {
		errs = append(errs, fmt.Errorf("%s: want a plain address such as no-reply@example.com", EnvMailFrom))
	} else {
		smtp.From = from
	}
	smtp.FromName = strings.TrimSpace(value(lookup, EnvMailFromName))
	return errs
}
