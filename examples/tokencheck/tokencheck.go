package tokencheck

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	tokenType = "at+jwt"
	// maxJWKSBytes bounds the key set a server may send.
	maxJWKSBytes = 64 << 10
	// maxTokenBytes bounds the token a client may send.
	maxTokenBytes = 4096
)

// ErrInvalidToken reports a token that must not authenticate anyone. The reason is in the
// wrapped message for logs; show a client nothing but a 401.
var ErrInvalidToken = errors.New("invalid access token")

// Config is what a service must know about the issuer.
type Config struct {
	// Issuer and Audience are the exact expected iss and aud values.
	Issuer   string
	Audience string
	// JWKSURL is where the issuer publishes its public keys. It must be https, except for
	// a loopback address used in development.
	JWKSURL string
	// Leeway is the clock skew tolerated for exp, nbf and iat; 30 seconds if zero.
	Leeway time.Duration
	// MaxKeyAge is how long a fetched key set is trusted without a refresh; 5 minutes if zero.
	MaxKeyAge time.Duration
	// MinRefetch spaces refreshes triggered by unknown key IDs, so a client cannot make the
	// service hammer the issuer; 30 seconds if zero.
	MinRefetch time.Duration
	// Client fetches the key set; a client with a 5 second timeout if nil.
	Client *http.Client
	// Now is the clock; time.Now if nil.
	Now func() time.Time
}

// Claims are the facts of a verified token.
type Claims struct {
	// Subject is the user ID (the sub claim): the key of the service's own user profile.
	Subject   string
	SessionID string
	AuthTime  time.Time
	AMR       []string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Verifier verifies access tokens against the issuer's key set.
type Verifier struct {
	cfg Config

	mu        sync.Mutex
	keys      map[string]*ecdsa.PublicKey
	fetchedAt time.Time
	// attemptedAt is the time of the last fetch, successful or not.
	attemptedAt time.Time
}

// New checks the configuration. It does not contact the issuer; the first token does.
func New(cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" || cfg.Audience == "" {
		return nil, errors.New("tokencheck: the expected issuer and audience are required")
	}
	u, err := url.Parse(cfg.JWKSURL)
	if err != nil || u.Host == "" || u.User != nil {
		return nil, errors.New("tokencheck: a JWKS URL is required")
	}
	if u.Scheme != "https" && (u.Scheme != "http" || !isLoopback(u.Hostname())) {
		return nil, errors.New("tokencheck: the JWKS URL must be https (http only for a loopback address)")
	}
	if cfg.Leeway < 0 || cfg.MaxKeyAge < 0 || cfg.MinRefetch < 0 {
		return nil, errors.New("tokencheck: durations must not be negative")
	}
	if cfg.Leeway == 0 {
		cfg.Leeway = 30 * time.Second
	}
	if cfg.MaxKeyAge == 0 {
		cfg.MaxKeyAge = 5 * time.Minute
	}
	if cfg.MinRefetch == 0 {
		cfg.MinRefetch = 30 * time.Second
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 5 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Verifier{cfg: cfg}, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func invalid(reason string) error { return fmt.Errorf("%w: %s", ErrInvalidToken, reason) }

// Verify checks the token and returns its claims. Every refusal wraps ErrInvalidToken; any
// other error is a failure to reach the issuer's keys.
func (v *Verifier) Verify(ctx context.Context, token string) (Claims, error) {
	if token == "" || len(token) > maxTokenBytes {
		return Claims{}, invalid("missing or oversized token")
	}
	if err := checkHeaderNames(token); err != nil {
		return Claims{}, err
	}
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return Claims{}, invalid("not a signed ES256 token")
	}
	if len(parsed.Headers) != 1 {
		return Claims{}, invalid("exactly one signature is expected")
	}
	header := parsed.Headers[0]
	if typ, _ := header.ExtraHeaders[jose.HeaderType].(string); typ != tokenType {
		return Claims{}, invalid("not an access token")
	}
	if header.KeyID == "" {
		return Claims{}, invalid("no key id")
	}
	key, err := v.key(ctx, header.KeyID)
	if err != nil {
		return Claims{}, err
	}

	var std jwt.Claims
	var private struct {
		SessionID string           `json:"sid"`
		AuthTime  *jwt.NumericDate `json:"auth_time"`
		AMR       []string         `json:"amr"`
	}
	if err := parsed.Claims(key, &std, &private); err != nil {
		return Claims{}, invalid("signature does not verify")
	}
	err = std.ValidateWithLeeway(jwt.Expected{
		Issuer: v.cfg.Issuer, AnyAudience: jwt.Audience{v.cfg.Audience}, Time: v.cfg.Now(),
	}, v.cfg.Leeway)
	if err != nil {
		return Claims{}, invalid("issuer, audience or time check failed")
	}
	if std.Subject == "" || std.Expiry == nil || std.IssuedAt == nil || private.SessionID == "" || private.AuthTime == nil || len(private.AMR) == 0 {
		return Claims{}, invalid("a required claim is missing")
	}
	return Claims{
		Subject: std.Subject, SessionID: private.SessionID, AuthTime: private.AuthTime.Time().UTC(), AMR: private.AMR,
		IssuedAt: std.IssuedAt.Time().UTC(), ExpiresAt: std.Expiry.Time().UTC(),
	}, nil
}

// key returns the public key of a kid, refreshing the key set when it is stale or when the
// kid is new, but never more often than MinRefetch.
func (v *Verifier) key(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.cfg.Now()

	stale := v.keys == nil || now.Sub(v.fetchedAt) > v.cfg.MaxKeyAge
	if key, ok := v.keys[kid]; ok && !stale {
		return key, nil
	}
	if v.keys == nil || now.Sub(v.attemptedAt) >= v.cfg.MinRefetch {
		if err := v.refresh(ctx, now); err != nil && v.keys == nil {
			return nil, err
		}
	}
	if key, ok := v.keys[kid]; ok {
		return key, nil
	}
	return nil, invalid("unknown key id")
}

// refresh replaces the key set. A failed refresh keeps the old set, so an issuer outage
// does not log everyone out, but the set is never trusted past what was last fetched
// without noticing: the caller still sees the error when there is no set at all.
func (v *Verifier) refresh(ctx context.Context, now time.Time) error {
	v.attemptedAt = now
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.JWKSURL, nil)
	if err != nil {
		return err
	}
	resp, err := v.cfg.Client.Do(req)
	if err != nil {
		return fmt.Errorf("tokencheck: fetch the key set: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("tokencheck: the key set answered %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil || len(data) > maxJWKSBytes {
		return errors.New("tokencheck: the key set is unreadable or too large")
	}
	keys, err := parseKeys(data)
	if err != nil {
		return err
	}
	v.keys, v.fetchedAt = keys, now
	return nil
}

// parseKeys keeps only EC P-256 signing keys with a kid. Anything else in the set is
// ignored, so an unrelated key cannot be used to verify access tokens.
func parseKeys(data []byte) (map[string]*ecdsa.PublicKey, error) {
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, errors.New("tokencheck: the key set is not valid JWKS")
	}
	keys := map[string]*ecdsa.PublicKey{}
	for _, k := range set.Keys {
		pub, ok := k.Key.(*ecdsa.PublicKey)
		if !ok || !k.IsPublic() || k.KeyID == "" || pub.Curve != elliptic.P256() {
			continue
		}
		if k.Use != "" && k.Use != "sig" || k.Algorithm != "" && k.Algorithm != string(jose.ES256) {
			continue
		}
		keys[k.KeyID] = pub
	}
	if len(keys) == 0 {
		return nil, errors.New("tokencheck: the key set holds no usable key")
	}
	return keys, nil
}

// checkHeaderNames refuses a header that names anything but alg, typ and kid, or names one
// twice: jwk, jku, x5u, x5c and crit change how a key is found or what the rules are.
func checkHeaderNames(token string) error {
	segment, _, _ := strings.Cut(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return invalid("unreadable header")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return invalid("header is not an object")
	}
	seen := map[string]bool{}
	for dec.More() {
		nameTok, err := dec.Token()
		if err != nil {
			return invalid("unreadable header")
		}
		name, _ := nameTok.(string)
		if name != "alg" && name != "typ" && name != "kid" {
			return invalid("unexpected header")
		}
		if seen[name] {
			return invalid("repeated header")
		}
		seen[name] = true
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return invalid("unreadable header")
		}
	}
	return nil
}
