package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Registration modes.
const (
	RegistrationOpen   = "open"
	RegistrationInvite = "invite"
)

const (
	// EnvLogLevel selects the minimum log level: debug, info, warn or error.
	EnvLogLevel = "AIRLANCE_AUTH_LOG_LEVEL"
	// EnvLogFormat selects the log encoding: json or text.
	EnvLogFormat = "AIRLANCE_AUTH_LOG_FORMAT"
	// EnvShutdownTimeout bounds graceful shutdown, as a Go duration such as 15s.
	EnvShutdownTimeout = "AIRLANCE_AUTH_SHUTDOWN_TIMEOUT"
	// EnvDatabaseURL is the PostgreSQL connection URL. It holds a password and is never logged.
	EnvDatabaseURL = "AIRLANCE_AUTH_DATABASE_URL"
	// EnvDatabaseMaxConns caps the connection pool; unset keeps the driver default (the
	// larger of 4 and the number of CPUs).
	EnvDatabaseMaxConns = "AIRLANCE_AUTH_DATABASE_MAX_CONNS"
	// EnvOIDCIssuer turns the OpenID Provider on and is its issuer: the origin the discovery document, the login
	// page and every endpoint are served from, such as https://auth.example.com. It must be one of the WebAuthn
	// origins, because the sign-in page runs there.
	EnvOIDCIssuer = "AIRLANCE_AUTH_OIDC_ISSUER"
	// EnvOIDCBackchannelAllow lists the internal networks the provider may call to deliver back-channel logout notices, as
	// comma-separated CIDRs or IPs. Private, loopback and link-local addresses are refused otherwise, so a client's
	// address cannot be used to reach the provider's own network.
	EnvOIDCBackchannelAllow = "AIRLANCE_AUTH_OIDC_BACKCHANNEL_ALLOW"
	// EnvDatabaseSchema names the PostgreSQL schema that holds the service's tables and its
	// migration history. The schema is created by migrate. Unset means DefaultDatabaseSchema, unless the
	// connection URL carries its own search_path, which is then left alone.
	EnvDatabaseSchema = "AIRLANCE_AUTH_DATABASE_SCHEMA"
	// EnvJWTIssuer is the iss claim of access tokens and the issuer verifiers expect.
	EnvJWTIssuer = "AIRLANCE_AUTH_JWT_ISSUER"
	// EnvJWTAudience is the single aud claim of access tokens.
	EnvJWTAudience = "AIRLANCE_AUTH_JWT_AUDIENCE"
	// EnvAccessTTL is the lifetime of an access token, as a Go duration.
	EnvAccessTTL = "AIRLANCE_AUTH_ACCESS_TTL"
	// EnvSMTPAddr is host:port of the SMTP server. Setting it turns the mail worker on.
	EnvSMTPAddr = "AIRLANCE_AUTH_SMTP_ADDR"
	// EnvSMTPTLS is none, starttls (default) or tls. none is for local development only.
	EnvSMTPTLS = "AIRLANCE_AUTH_SMTP_TLS"
	// EnvSMTPUsername and EnvSMTPPassword enable SMTP authentication; both or neither.
	EnvSMTPUsername = "AIRLANCE_AUTH_SMTP_USERNAME"
	EnvSMTPPassword = "AIRLANCE_AUTH_SMTP_PASSWORD"
	// EnvMailFrom is the sender address of the emails; EnvMailFromName is an optional display name.
	EnvMailFrom     = "AIRLANCE_AUTH_MAIL_FROM"
	EnvMailFromName = "AIRLANCE_AUTH_MAIL_FROM_NAME"
	// EnvKeyringFile is the path of the keyring JSON file.
	EnvKeyringFile = "AIRLANCE_AUTH_KEYRING_FILE"
	// EnvRegistration is open (default) or invite: with invite only an invited address can create an account.
	EnvRegistration = "AIRLANCE_AUTH_REGISTRATION"
	// EnvInvitationURL is the link an invitation email points to: the page where an invited address signs in.
	// Unset, it is the JWT issuer.
	EnvInvitationURL = "AIRLANCE_AUTH_INVITATION_URL"
	// EnvAdminAddr is the ip:port of the admin API listener. Unset, there is no admin API. Beyond the
	// loopback it needs EnvTrustedProxies.
	EnvAdminAddr = "AIRLANCE_AUTH_ADMIN_ADDR"
	// EnvAdminRPID and EnvAdminOrigins are the relying party of operators' passkeys and the exact origins of the
	// admin page. The relying party must differ from the users': an operator's page never offers a user's key.
	EnvAdminRPID    = "AIRLANCE_AUTH_ADMIN_RP_ID"
	EnvAdminOrigins = "AIRLANCE_AUTH_ADMIN_ORIGINS"
	// EnvTrustedProxies lists the CIDR networks of the reverse proxies whose
	// X-Forwarded-For header is believed. Without it the TCP peer is the client.
	EnvTrustedProxies = "AIRLANCE_AUTH_TRUSTED_PROXIES"
	// EnvBrowserOrigins lists the exact origins of the pages that may call the browser
	// profile from another origin. The API's own origin needs no entry.
	EnvBrowserOrigins = "AIRLANCE_AUTH_BROWSER_ORIGINS"
	// EnvCookieSameSite is the SameSite attribute of the browser cookies: strict (default),
	// lax or none. None is for a deliberately cross-site deployment.
	EnvCookieSameSite = "AIRLANCE_AUTH_COOKIE_SAMESITE"
	// EnvHTTPAddr is the ip:port of the HTTP API. Setting it turns the API on. Beyond the loopback
	// (0.0.0.0:8080 in a container) it needs EnvTrustedProxies.
	EnvHTTPAddr = "AIRLANCE_AUTH_HTTP_ADDR"
	// EnvMetricsAddr is the ip:port of the metrics listener, which has no authentication: do not publish it. When set, GET /metrics
	// is served there and no longer on the API listener.
	EnvMetricsAddr = "AIRLANCE_AUTH_METRICS_ADDR"
	// EnvWebAuthnRPID is the relying party ID passkeys are bound to: the registrable domain of
	// the site, such as example.com, or localhost in development. Required with the API.
	EnvWebAuthnRPID = "AIRLANCE_AUTH_WEBAUTHN_RP_ID"
	// EnvWebAuthnRPName is the name an authenticator shows; it defaults to the relying party ID.
	EnvWebAuthnRPName = "AIRLANCE_AUTH_WEBAUTHN_RP_NAME"
	// EnvWebAuthnOrigins lists the exact origins that may run a ceremony: https origins of the
	// pages (http only for localhost) and android:apk-key-hash:... origins of native apps.
	// Required with the API.
	EnvWebAuthnOrigins = "AIRLANCE_AUTH_WEBAUTHN_ORIGINS"
)

// SMTP TLS modes.
const (
	SMTPTLSNone     = "none"
	SMTPTLSStartTLS = "starttls"
	SMTPTLSImplicit = "tls"
)

// Log encodings.
const (
	LogFormatJSON = "json"
	LogFormatText = "text"
)

const (
	defaultShutdownTimeout = 15 * time.Second
	defaultAccessTTL       = 5 * time.Minute
	// maxAccessTTL guards against a typo turning a short-lived token into a long-lived one.
	maxAccessTTL = time.Hour
)

// Config is the validated service configuration.
type Config struct {
	Log             LogConfig
	ShutdownTimeout time.Duration
	// HTTP is empty (Addr == "") until the API is wanted.
	HTTP HTTPConfig
	// Metrics is empty (Addr == "") while /metrics stays on the API listener.
	Metrics MetricsConfig
	// WebAuthn is the relying party of passkeys; the API needs it.
	WebAuthn WebAuthnConfig
	// JWT holds the access token settings; Issuer and Audience are required once
	// the keyring has a jwt_signing purpose.
	JWT JWTConfig
	// SMTP is empty (Host == "") until the mail worker is wanted.
	SMTP SMTPConfig
	// Admin is empty (Addr == "") until the admin API is wanted.
	Admin AdminConfig
	// OIDC is empty (Issuer == "") until the OpenID Provider is wanted.
	OIDC OIDCConfig
	// Registration is RegistrationOpen or RegistrationInvite.
	Registration string
	// InvitationURL is the link of the invitation email; empty when neither it nor the issuer is set.
	InvitationURL string
	// Database is unset until a command needs it; migrate requires it.
	Database DatabaseConfig
	// Keyring is nil until a keyring file is configured. Each feature that
	// needs a purpose requires it when that feature is wired in.
	Keyring *Keyring
}

// HTTPConfig holds the API listener settings. When Addr is set the service also needs
// the database and both key purposes, because the API starts flows and signs tokens.
type HTTPConfig struct {
	Addr string
	// TrustedProxies are the networks whose forwarding headers are believed.
	TrustedProxies []netip.Prefix
	// BrowserOrigins are the exact trusted origins of browser pages on other origins.
	BrowserOrigins []string
	// CookieSameSite is "strict", "lax" or "none"; "" means strict.
	CookieSameSite string
}

// Enabled reports whether the API is configured.
func (c HTTPConfig) Enabled() bool { return c.Addr != "" }

// AdminConfig holds the admin API listener and the relying party of operators' passkeys.
type AdminConfig struct {
	Addr    string
	RPID    string
	Origins []string
}

// Enabled reports whether the admin API is configured.
func (c AdminConfig) Enabled() bool { return c.Addr != "" }

// WebAuthnConfig holds the relying party of passkeys.
type WebAuthnConfig struct {
	RPID    string
	RPName  string
	Origins []string
}

// MetricsConfig holds the settings of the separate metrics listener.
type MetricsConfig struct {
	Addr string
}

// Enabled reports whether the metrics listener is configured.
func (c MetricsConfig) Enabled() bool { return c.Addr != "" }

// SMTPConfig holds the mail delivery settings. When Host is set the service also needs
// the database and the OTP keys, because the worker reads flows and derives codes.
type SMTPConfig struct {
	Host     string
	Port     int
	TLS      string
	Username string
	Password Secret
	From     string
	FromName string
}

// Enabled reports whether the mail worker is configured.
func (c SMTPConfig) Enabled() bool { return c.Host != "" }

// JWTConfig holds the claims every access token carries and its lifetime.
type JWTConfig struct {
	Issuer    string
	Audience  string
	AccessTTL time.Duration
}

// OIDCConfig holds the OpenID Provider settings.
type OIDCConfig struct {
	// Issuer is an origin without a trailing slash, as it appears in the iss claim and the discovery document.
	Issuer string
	// BackchannelAllow are the internal networks a logout notice may be delivered to.
	BackchannelAllow []netip.Prefix
}

// Enabled reports whether the OpenID Provider is on.
func (c OIDCConfig) Enabled() bool { return c.Issuer != "" }

// DatabaseConfig holds the database connection settings.
type DatabaseConfig struct {
	URL Secret
	// MaxConns is the pool cap; 0 keeps the driver default.
	MaxConns int32
	// Schema is the schema of the service's tables. Empty keeps the search_path of the connection URL.
	Schema string
}

// LogConfig controls the process logger.
type LogConfig struct {
	Level  slog.Level
	Format string
}

// LookupFunc reads one configuration value, like os.LookupEnv.
type LookupFunc func(key string) (string, bool)

// Load builds Config from lookup. A variable that is unset or empty takes its
// default. All invalid values are reported together.
func Load(lookup LookupFunc) (Config, error) {
	cfg := Config{
		Log:             LogConfig{Level: slog.LevelInfo, Format: LogFormatJSON},
		ShutdownTimeout: defaultShutdownTimeout,
		JWT:             JWTConfig{AccessTTL: defaultAccessTTL},
		Database:        DatabaseConfig{Schema: DefaultDatabaseSchema},
		SMTP:            SMTPConfig{TLS: SMTPTLSStartTLS},
		Registration:    RegistrationOpen,
	}
	var errs []error

	if v := value(lookup, EnvLogLevel); v != "" {
		if err := cfg.Log.Level.UnmarshalText([]byte(v)); err != nil || !knownLevel(v) {
			errs = append(errs, fmt.Errorf("%s: want debug, info, warn or error", EnvLogLevel))
		}
	}
	if v := value(lookup, EnvLogFormat); v != "" {
		switch v {
		case LogFormatJSON, LogFormatText:
			cfg.Log.Format = v
		default:
			errs = append(errs, fmt.Errorf("%s: want %s or %s", EnvLogFormat, LogFormatJSON, LogFormatText))
		}
	}
	if v := value(lookup, EnvShutdownTimeout); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			errs = append(errs, fmt.Errorf("%s: want a positive duration such as 15s", EnvShutdownTimeout))
		} else {
			cfg.ShutdownTimeout = d
		}
	}
	cfg.JWT.Issuer = strings.TrimSpace(value(lookup, EnvJWTIssuer))
	cfg.JWT.Audience = strings.TrimSpace(value(lookup, EnvJWTAudience))
	if v := value(lookup, EnvAccessTTL); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 || d > maxAccessTTL {
			errs = append(errs, fmt.Errorf("%s: want a duration above 0 and at most %s", EnvAccessTTL, maxAccessTTL))
		} else {
			cfg.JWT.AccessTTL = d
		}
	}
	if v := value(lookup, EnvRegistration); v != "" {
		switch v {
		case RegistrationOpen, RegistrationInvite:
			cfg.Registration = v
		default:
			errs = append(errs, fmt.Errorf("%s: want %s or %s", EnvRegistration, RegistrationOpen, RegistrationInvite))
		}
	}
	if v := value(lookup, EnvInvitationURL); v != "" {
		if err := checkInvitationURL(v); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", EnvInvitationURL, err))
		} else {
			cfg.InvitationURL = v
		}
	} else if err := checkInvitationURL(cfg.JWT.Issuer); err == nil {
		cfg.InvitationURL = cfg.JWT.Issuer
	}
	errs = append(errs, loadSMTP(lookup, &cfg.SMTP)...)
	cfg.WebAuthn.RPID = strings.ToLower(value(lookup, EnvWebAuthnRPID))
	cfg.WebAuthn.RPName = value(lookup, EnvWebAuthnRPName)
	if cfg.WebAuthn.RPID != "" && !validRPID(cfg.WebAuthn.RPID) {
		errs = append(errs, fmt.Errorf("%s: want a domain such as example.com or localhost, without scheme, port or path", EnvWebAuthnRPID))
		cfg.WebAuthn.RPID = ""
	}
	if len(cfg.WebAuthn.RPName) > 64 {
		errs = append(errs, fmt.Errorf("%s: at most 64 characters", EnvWebAuthnRPName))
	}
	if v := value(lookup, EnvWebAuthnOrigins); v != "" {
		origins, err := parseWebAuthnOrigins(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", EnvWebAuthnOrigins, err))
		} else if cfg.WebAuthn.RPID != "" {
			if err := checkOriginsMatchRPID(origins, cfg.WebAuthn.RPID); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", EnvWebAuthnOrigins, err))
			} else {
				cfg.WebAuthn.Origins = origins
			}
		}
	}
	if v := value(lookup, EnvMetricsAddr); v != "" {
		if err := checkListenAddr(v); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", EnvMetricsAddr, err))
		} else {
			cfg.Metrics.Addr = v
		}
	}
	if v := value(lookup, EnvHTTPAddr); v != "" {
		if err := checkListenAddr(v); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", EnvHTTPAddr, err))
		} else {
			cfg.HTTP.Addr = v
		}
	}
	errs = append(errs, loadAdmin(lookup, &cfg)...)
	if v := value(lookup, EnvBrowserOrigins); v != "" {
		origins, err := parseBrowserOrigins(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", EnvBrowserOrigins, err))
		} else {
			cfg.HTTP.BrowserOrigins = origins
		}
	}
	if v := value(lookup, EnvCookieSameSite); v != "" {
		switch strings.ToLower(v) {
		case SameSiteStrict, SameSiteLax, SameSiteNone:
			cfg.HTTP.CookieSameSite = strings.ToLower(v)
		default:
			errs = append(errs, fmt.Errorf("%s: want strict, lax or none", EnvCookieSameSite))
		}
	}
	if v := value(lookup, EnvTrustedProxies); v != "" {
		proxies, err := parseTrustedProxies(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", EnvTrustedProxies, err))
		} else {
			cfg.HTTP.TrustedProxies = proxies
		}
	}
	// Past the loopback the service is reached through a proxy or an ingress: it speaks plain HTTP, its
	// cookies are Secure, and the client address comes from the proxy. Say which proxies to believe.
	for _, l := range []struct{ env, addr string }{{EnvHTTPAddr, cfg.HTTP.Addr}, {EnvAdminAddr, cfg.Admin.Addr}} {
		if ListensBeyondLoopback(l.addr) && len(cfg.HTTP.TrustedProxies) == 0 {
			errs = append(errs, fmt.Errorf("%s listens beyond the loopback, so %s is required: TLS and the client address come from the proxy in front of the service", l.env, EnvTrustedProxies))
		}
	}
	if v := value(lookup, EnvDatabaseMaxConns); v != "" {
		if n, err := strconv.Atoi(v); err != nil || n < 1 || n > maxDatabaseConns {
			errs = append(errs, fmt.Errorf("%s: want a number from 1 to %d", EnvDatabaseMaxConns, maxDatabaseConns))
		} else {
			cfg.Database.MaxConns = int32(n)
		}
	}
	schemaSet := false
	if v := value(lookup, EnvDatabaseSchema); v != "" {
		schemaSet = true
		if !databaseSchema.MatchString(v) || strings.HasPrefix(v, "pg_") {
			errs = append(errs, fmt.Errorf("%s: want lower-case letters, digits and underscores, starting with a letter or underscore, at most 63 characters, not starting with pg_", EnvDatabaseSchema))
		} else {
			cfg.Database.Schema = v
		}
	}
	if v := value(lookup, EnvDatabaseURL); v != "" {
		if u, err := url.Parse(v); err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Host == "" {
			// The message must not echo the value: it contains a password.
			errs = append(errs, fmt.Errorf("%s: want a postgres:// URL with a host", EnvDatabaseURL))
		} else {
			cfg.Database.URL = NewSecret(v)
			// An explicit search_path in the URL is the operator's choice; the default does not override it.
			if !schemaSet && u.Query().Has("search_path") {
				cfg.Database.Schema = ""
			}
		}
	}
	if v := value(lookup, EnvKeyringFile); v != "" {
		ring, err := LoadKeyring(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", EnvKeyringFile, err))
		} else {
			cfg.Keyring = ring
		}
	}

	if cfg.Keyring != nil && cfg.Keyring.JWTSigning != nil {
		if cfg.JWT.Issuer == "" {
			errs = append(errs, fmt.Errorf("%s is required when the keyring has jwt_signing", EnvJWTIssuer))
		}
		if cfg.JWT.Audience == "" {
			errs = append(errs, fmt.Errorf("%s is required when the keyring has jwt_signing", EnvJWTAudience))
		}
	}

	if cfg.SMTP.Enabled() {
		if !cfg.Database.URL.IsSet() {
			errs = append(errs, fmt.Errorf("%s is required when %s is set: the mail worker reads the queue from the database", EnvDatabaseURL, EnvSMTPAddr))
		}
		if cfg.Keyring == nil || cfg.Keyring.OTPHMAC == nil {
			errs = append(errs, fmt.Errorf("an otp_hmac keyring is required when %s is set: the worker derives the codes", EnvSMTPAddr))
		}
	}

	if cfg.HTTP.Enabled() {
		if !cfg.Database.URL.IsSet() {
			errs = append(errs, fmt.Errorf("%s is required when %s is set: the API stores flows and sessions", EnvDatabaseURL, EnvHTTPAddr))
		}
		if cfg.Keyring == nil || cfg.Keyring.OTPHMAC == nil {
			errs = append(errs, fmt.Errorf("an otp_hmac keyring is required when %s is set: start and verify derive the codes", EnvHTTPAddr))
		}
		if cfg.Keyring == nil || cfg.Keyring.JWTSigning == nil {
			errs = append(errs, fmt.Errorf("a jwt_signing keyring is required when %s is set: verify and refresh sign access tokens", EnvHTTPAddr))
		}
		if value(lookup, EnvWebAuthnRPID) == "" {
			errs = append(errs, fmt.Errorf("%s is required when %s is set: a session needs a passkey", EnvWebAuthnRPID, EnvHTTPAddr))
		}
		if value(lookup, EnvWebAuthnOrigins) == "" {
			errs = append(errs, fmt.Errorf("%s is required when %s is set: a session needs a passkey", EnvWebAuthnOrigins, EnvHTTPAddr))
		}
	}
	errs = append(errs, loadOIDC(lookup, &cfg)...)
	if cfg.Admin.Enabled() {
		if !cfg.Database.URL.IsSet() {
			errs = append(errs, fmt.Errorf("%s is required when %s is set: operators and their sessions are stored there", EnvDatabaseURL, EnvAdminAddr))
		}
		if cfg.Admin.Addr == cfg.HTTP.Addr || cfg.Admin.Addr == cfg.Metrics.Addr {
			errs = append(errs, fmt.Errorf("%s must differ from %s and %s: the point is a separate listener", EnvAdminAddr, EnvHTTPAddr, EnvMetricsAddr))
		}
	}
	if cfg.Metrics.Enabled() {
		if !cfg.SMTP.Enabled() && !cfg.HTTP.Enabled() {
			errs = append(errs, fmt.Errorf("%s needs %s or %s: there is nothing to measure otherwise", EnvMetricsAddr, EnvHTTPAddr, EnvSMTPAddr))
		}
		if cfg.Metrics.Addr == cfg.HTTP.Addr {
			errs = append(errs, fmt.Errorf("%s must differ from %s: the point is a separate listener", EnvMetricsAddr, EnvHTTPAddr))
		}
	}
	if cfg.HTTP.CookieSameSite == SameSiteNone && len(cfg.HTTP.BrowserOrigins) == 0 {
		errs = append(errs, fmt.Errorf("%s=none needs a trusted origin in %s: SameSite=None cookies are sent cross-site", EnvCookieSameSite, EnvBrowserOrigins))
	}

	if err := errors.Join(errs...); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

var databaseSchema = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// maxDatabaseConns bounds the pool setting: PostgreSQL itself allows 100 connections by default.
const maxDatabaseConns = 100

// DefaultDatabaseSchema is where the service keeps its tables when nothing says otherwise.
const DefaultDatabaseSchema = "auth"

// SameSite values of EnvCookieSameSite.
const (
	SameSiteStrict = "strict"
	SameSiteLax    = "lax"
	SameSiteNone   = "none"
)

func value(lookup LookupFunc, key string) string {
	v, _ := lookup(key)
	return v
}

// knownLevel rejects slog's "INFO+2" offset syntax; only the four names are documented.
func knownLevel(v string) bool {
	switch v {
	case "debug", "info", "warn", "error", "DEBUG", "INFO", "WARN", "ERROR":
		return true
	}
	return false
}
