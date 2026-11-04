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

const (
	RegistrationOpen   = "open"
	RegistrationInvite = "invite"
)

const (
	EnvLogLevel             = "AIRLANCE_AUTH_LOG_LEVEL"
	EnvLogFormat            = "AIRLANCE_AUTH_LOG_FORMAT"
	EnvShutdownTimeout      = "AIRLANCE_AUTH_SHUTDOWN_TIMEOUT"
	EnvDatabaseURL          = "AIRLANCE_AUTH_DATABASE_URL"
	EnvDatabaseMaxConns     = "AIRLANCE_AUTH_DATABASE_MAX_CONNS"
	EnvOIDCIssuer           = "AIRLANCE_AUTH_OIDC_ISSUER"
	EnvOIDCBackchannelAllow = "AIRLANCE_AUTH_OIDC_BACKCHANNEL_ALLOW"
	EnvDatabaseSchema       = "AIRLANCE_AUTH_DATABASE_SCHEMA"
	EnvJWTIssuer            = "AIRLANCE_AUTH_JWT_ISSUER"
	EnvJWTAudience          = "AIRLANCE_AUTH_JWT_AUDIENCE"
	EnvAccessTTL            = "AIRLANCE_AUTH_ACCESS_TTL"
	EnvSMTPAddr             = "AIRLANCE_AUTH_SMTP_ADDR"
	EnvSMTPTLS              = "AIRLANCE_AUTH_SMTP_TLS"
	EnvSMTPUsername         = "AIRLANCE_AUTH_SMTP_USERNAME"
	EnvSMTPPassword         = "AIRLANCE_AUTH_SMTP_PASSWORD"
	EnvMailFrom             = "AIRLANCE_AUTH_MAIL_FROM"
	EnvMailFromName         = "AIRLANCE_AUTH_MAIL_FROM_NAME"
	EnvKeyringFile          = "AIRLANCE_AUTH_KEYRING_FILE"
	EnvRegistration         = "AIRLANCE_AUTH_REGISTRATION"
	EnvInvitationURL        = "AIRLANCE_AUTH_INVITATION_URL"
	EnvAdminAddr            = "AIRLANCE_AUTH_ADMIN_ADDR"
	EnvAdminRPID            = "AIRLANCE_AUTH_ADMIN_RP_ID"
	EnvAdminOrigins         = "AIRLANCE_AUTH_ADMIN_ORIGINS"
	EnvTrustedProxies       = "AIRLANCE_AUTH_TRUSTED_PROXIES"
	EnvBrowserOrigins       = "AIRLANCE_AUTH_BROWSER_ORIGINS"
	EnvAppleAppIDs          = "AIRLANCE_AUTH_APPLE_APP_IDS"
	EnvCookieSameSite       = "AIRLANCE_AUTH_COOKIE_SAMESITE"
	EnvHTTPAddr             = "AIRLANCE_AUTH_HTTP_ADDR"
	EnvMetricsAddr          = "AIRLANCE_AUTH_METRICS_ADDR"
	EnvWebAuthnRPID         = "AIRLANCE_AUTH_WEBAUTHN_RP_ID"
	EnvWebAuthnRPName       = "AIRLANCE_AUTH_WEBAUTHN_RP_NAME"
	EnvWebAuthnOrigins      = "AIRLANCE_AUTH_WEBAUTHN_ORIGINS"
)

const (
	SMTPTLSNone     = "none"
	SMTPTLSStartTLS = "starttls"
	SMTPTLSImplicit = "tls"
)

const (
	LogFormatJSON = "json"
	LogFormatText = "text"
)

const (
	defaultShutdownTimeout = 15 * time.Second
	defaultAccessTTL       = 5 * time.Minute
	maxAccessTTL           = time.Hour
)

type Config struct {
	Log             LogConfig
	ShutdownTimeout time.Duration
	HTTP            HTTPConfig
	Metrics         MetricsConfig
	WebAuthn        WebAuthnConfig
	JWT             JWTConfig
	SMTP            SMTPConfig
	Admin           AdminConfig
	OIDC            OIDCConfig
	Registration    string
	InvitationURL   string
	Database        DatabaseConfig
	Keyring         *Keyring
}

type HTTPConfig struct {
	Addr           string
	TrustedProxies []netip.Prefix
	BrowserOrigins []string
	CookieSameSite string
	AppleAppIDs    []string
}

func (c HTTPConfig) Enabled() bool {
	return c.Addr != ""
}

type AdminConfig struct {
	Addr    string
	RPID    string
	Origins []string
}

func (c AdminConfig) Enabled() bool {
	return c.Addr != ""
}

type WebAuthnConfig struct {
	RPID    string
	RPName  string
	Origins []string
}

type MetricsConfig struct {
	Addr string
}

func (c MetricsConfig) Enabled() bool {
	return c.Addr != ""
}

type SMTPConfig struct {
	Host     string
	Port     int
	TLS      string
	Username string
	Password Secret
	From     string
	FromName string
}

func (c SMTPConfig) Enabled() bool {
	return c.Host != ""
}

type JWTConfig struct {
	Issuer    string
	Audience  string
	AccessTTL time.Duration
}

type OIDCConfig struct {
	Issuer           string
	BackchannelAllow []netip.Prefix
}

func (c OIDCConfig) Enabled() bool {
	return c.Issuer != ""
}

type DatabaseConfig struct {
	URL      Secret
	MaxConns int32
	Schema   string
}

type LogConfig struct {
	Level  slog.Level
	Format string
}

type LookupFunc func(key string) (string, bool)

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

	if v := value(lookup, EnvAppleAppIDs); v != "" {
		ids, err := parseAppleAppIDs(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", EnvAppleAppIDs, err))
		} else {
			cfg.HTTP.AppleAppIDs = ids
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
			errs = append(errs, fmt.Errorf("%s: want a postgres:// URL with a host", EnvDatabaseURL))
		} else {
			cfg.Database.URL = NewSecret(v)

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

const maxDatabaseConns = 100

const DefaultDatabaseSchema = "auth"

const (
	SameSiteStrict = "strict"
	SameSiteLax    = "lax"
	SameSiteNone   = "none"
)

func value(lookup LookupFunc, key string) string {
	v, _ := lookup(key)
	return v
}

func knownLevel(v string) bool {
	switch v {
	case "debug", "info", "warn", "error", "DEBUG", "INFO", "WARN", "ERROR":
		return true
	}

	return false
}
