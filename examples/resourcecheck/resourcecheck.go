// Package resourcecheck is what an API puts in front of its handlers to accept the access tokens of the OpenID Provider
// (airlance-auth) and nothing else. It is an example to copy into a service, not a dependency of the provider: it needs
// only the issuer's address, the API's own audience, and the key set the issuer publishes.
//
// A service that uses it must know three things about the tokens.
//
//   - A token is for one API. The audience is the one registered for this API (`oidc resource register --audience`), and a
//     token for another API is refused here even though its signature and its user are good. A client_id is not an
//     audience: ID tokens, which carry it, are refused by their type.
//   - A scope is a right to an operation, not to an object. Check the scope the handler needs (Require), and then whether
//     this user may touch this chat, file or organization: that is the API's own rule, and no scope replaces it. Never read
//     administrative rights out of the scopes of a user's token.
//   - The token is checked offline, by its signature, so a grant that ends is still honoured here until the token expires:
//     the provider issues them for five minutes, and Leeway is added to that. A service that cannot wait that long sets
//     Config.Introspection and uses Check, which asks the provider about every token (RFC 7662) after it has verified it.
//     Then a revoked application or a right taken away stops working at once, and an issuer that does not answer stops the
//     service too (503), because a refusal that cannot be had is not a yes.
package resourcecheck

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	// tokenType is the typ of an access token (RFC 9068). An ID token is plain JWT and a logout token is logout+jwt, so
	// neither can pass for one.
	tokenType = "at+jwt"
	// maxJWKSBytes and maxDiscoveryBytes bound what the issuer may send.
	maxJWKSBytes      = 64 << 10
	maxDiscoveryBytes = 64 << 10
	// maxIntrospectionBytes bounds an introspection answer.
	maxIntrospectionBytes = 16 << 10
	// maxTokenBytes bounds the token a client may send; the provider's are a few hundred bytes.
	maxTokenBytes = 4096
	// minRSABits is the smallest modulus accepted for a key of the key set.
	minRSABits = 2048
)

// ErrInvalidToken reports a token that must not authenticate anyone. The reason is in the wrapped message for logs; show a
// client nothing but a 401.
var ErrInvalidToken = errors.New("invalid access token")

// ErrIssuerUnavailable reports that no key of the issuer could be had: the service cannot tell a good token from a bad one.
var ErrIssuerUnavailable = errors.New("the issuer's keys are unavailable")

// Config is what an API must know about the issuer and about itself.
type Config struct {
	// Issuer is the exact expected iss, such as https://auth.example.com.
	Issuer string
	// Audience is the aud this API was registered with. Tokens for any other audience are refused.
	Audience string
	// JWKSURL is where the issuer publishes its public keys: the jwks_uri of its discovery document (see Discover). It
	// must be https, except for a loopback address used in development.
	JWKSURL string
	// Leeway is the clock skew tolerated for exp, nbf and iat; 30 seconds if zero.
	Leeway time.Duration
	// MaxKeyAge is how long a fetched key set is trusted without a refresh; 5 minutes if zero.
	MaxKeyAge time.Duration
	// MinRefetch spaces the refreshes that an unknown key ID causes, so a client cannot make the service hammer the issuer;
	// 30 seconds if zero.
	MinRefetch time.Duration
	// Introspection, when set, makes Check ask the issuer whether each token is still live. Nil keeps the checks offline.
	Introspection *Introspection
	// Client fetches the key set; a client with a 5 second timeout if nil.
	Client *http.Client
	// Now is the clock; time.Now if nil.
	Now func() time.Time
}

// Introspection is how an API asks the issuer about a token: the introspection_endpoint of its discovery document, and the
// credentials of this API's resource (`oidc resource rotate-secret`). They open nothing else, and the issuer answers only
// about tokens issued for this API.
type Introspection struct {
	// URL must be https, except for a loopback address used in development.
	URL string
	// ResourceID and Secret are the identifier of the resource and its introspection secret.
	ResourceID string
	Secret     string
}

// Claims are the facts of a verified token.
type Claims struct {
	// Subject is the user: the (iss, sub) pair is the key of the service's own profile of them, never the email. For the
	// token of a service identity (client_credentials) it is the client_id, and Service is true.
	Subject string
	// Service is true when the token belongs to a service identity, not to a person: there is no user, sign-in or grant
	// behind it. Check it before treating Subject as a person; an API that serves people only should refuse such tokens
	// (RequireUser), and one that serves services should check the ClientID against the services it knows.
	Service bool
	// ClientID is the application the token was issued to.
	ClientID string
	// Scope are the rights the token carries, each one whole: the list of the space-separated claim.
	Scope []string
	// GrantID names the grant the token comes from; SessionID is the shared sign-in (the sid of the logout tokens).
	GrantID   string
	SessionID string
	TokenID   string
	AuthTime  time.Time
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// HasScope reports whether the token carries the scope. Scopes are compared as whole elements, case included:
// messages:send:any is not messages:send.
func (c Claims) HasScope(scope string) bool {
	return slices.Contains(c.Scope, scope)
}

// Verifier verifies the access tokens of one API against the issuer's key set.
type Verifier struct {
	cfg Config

	mu          sync.Mutex
	keys        map[string]*rsa.PublicKey
	fetchedAt   time.Time
	attemptedAt time.Time
}

// New checks the configuration. It does not contact the issuer; the first token does.
func New(cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" || cfg.Audience == "" {
		return nil, errors.New("resourcecheck: the expected issuer and audience are required")
	}

	if err := trustedURL(cfg.JWKSURL); err != nil {
		return nil, fmt.Errorf("resourcecheck: the JWKS URL: %w", err)
	}

	if cfg.Leeway < 0 || cfg.MaxKeyAge < 0 || cfg.MinRefetch < 0 {
		return nil, errors.New("resourcecheck: durations must not be negative")
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

	if in := cfg.Introspection; in != nil {
		if err := trustedURL(in.URL); err != nil {
			return nil, fmt.Errorf("resourcecheck: the introspection URL: %w", err)
		}

		if in.ResourceID == "" || in.Secret == "" {
			return nil, errors.New("resourcecheck: the introspection credentials are required")
		}
	}

	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 5 * time.Second}
	}

	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	return &Verifier{cfg: cfg}, nil
}

// trustedURL accepts an https address, or an http one for a loopback host in development; no credentials, no fragment.
func trustedURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return errors.New("an absolute URL without credentials or a fragment is required")
	}

	if u.Scheme != "https" && (u.Scheme != "http" || !isLoopback(u.Hostname())) {
		return errors.New("must be https (http only for a loopback address)")
	}

	return nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}

	ip := net.ParseIP(host)

	return ip != nil && ip.IsLoopback()
}

func invalid(reason string) error {
	return fmt.Errorf("%w: %s", ErrInvalidToken, reason)
}

// Discover reads the issuer's discovery document and returns where its key set is. The document must name the issuer it was
// fetched from, and the key set must be on the same host, so a document cannot send the service to someone else's keys.
func Discover(ctx context.Context, client *http.Client, issuer string) (jwksURL string, err error) {
	if err := trustedURL(issuer); err != nil {
		return "", fmt.Errorf("resourcecheck: the issuer: %w", err)
	}

	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(issuer, "/")+"/.well-known/openid-configuration", nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("resourcecheck: fetch the discovery document: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("resourcecheck: the discovery document answered %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDiscoveryBytes+1))
	if err != nil || len(data) > maxDiscoveryBytes {
		return "", errors.New("resourcecheck: the discovery document is unreadable or too large")
	}

	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(data, &doc); err != nil || doc.Issuer != issuer {
		return "", errors.New("resourcecheck: the discovery document is not the issuer's")
	}

	if err := trustedURL(doc.JWKSURI); err != nil {
		return "", fmt.Errorf("resourcecheck: jwks_uri: %w", err)
	}

	a, _ := url.Parse(issuer)

	b, _ := url.Parse(doc.JWKSURI)
	if a.Host != b.Host {
		return "", errors.New("resourcecheck: jwks_uri is not on the issuer's host")
	}

	return doc.JWKSURI, nil
}

// Verify checks the token and returns its claims. Every refusal wraps ErrInvalidToken; an issuer whose keys cannot be had
// wraps ErrIssuerUnavailable.
func (v *Verifier) Verify(ctx context.Context, token string) (Claims, error) {
	if token == "" || len(token) > maxTokenBytes || strings.Count(token, ".") != 2 {
		return Claims{}, invalid("missing, oversized or not a compact JWT")
	}

	if err := checkHeaderNames(token); err != nil {
		return Claims{}, err
	}

	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return Claims{}, invalid("not a signed RS256 token")
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

	var (
		std     jwt.Claims
		private struct {
			ClientID  string           `json:"client_id"`
			Scope     string           `json:"scope"`
			SessionID string           `json:"sid"`
			GrantID   string           `json:"grant_id"`
			AuthTime  *jwt.NumericDate `json:"auth_time"`
		}
	)
	if err := parsed.Claims(key, &std, &private); err != nil {
		return Claims{}, invalid("signature does not verify")
	}
	// The audience must be exactly this API's, and the only one: a token for two APIs is a token for neither.
	if len(std.Audience) != 1 {
		return Claims{}, invalid("exactly one audience is expected")
	}

	err = std.ValidateWithLeeway(jwt.Expected{Issuer: v.cfg.Issuer, AnyAudience: jwt.Audience{v.cfg.Audience}, Time: v.cfg.Now()}, v.cfg.Leeway)
	if err != nil {
		return Claims{}, invalid("issuer, audience or time check failed")
	}

	if std.Subject == "" || std.Expiry == nil || std.IssuedAt == nil || std.ID == "" || private.ClientID == "" || private.Scope == "" {
		return Claims{}, invalid("a required claim is missing")
	}

	if !std.Expiry.Time().After(std.IssuedAt.Time()) {
		return Claims{}, invalid("expiry is not after issue time")
	}

	if strings.TrimSpace(private.Scope) != private.Scope || strings.Contains(private.Scope, "  ") {
		return Claims{}, invalid("the scope is not a list separated by single spaces")
	}

	claims := Claims{
		Subject: std.Subject, ClientID: private.ClientID, Scope: strings.Split(private.Scope, " "), GrantID: private.GrantID,
		SessionID: private.SessionID, TokenID: std.ID, Service: std.Subject == private.ClientID, IssuedAt: std.IssuedAt.Time().UTC(), ExpiresAt: std.Expiry.Time().UTC(),
	}
	if private.AuthTime != nil {
		claims.AuthTime = private.AuthTime.Time().UTC()
	}

	return claims, nil
}

// Check is Verify and then, when Config.Introspection is set, the issuer's own answer: the token must be live there too.
// A token the issuer calls inactive is ErrInvalidToken. An answer that cannot be had (the issuer is down, refuses these
// credentials, or says something that does not fit the token) is ErrIssuerUnavailable, never a pass.
func (v *Verifier) Check(ctx context.Context, token string) (Claims, error) {
	claims, err := v.Verify(ctx, token)
	if err != nil || v.cfg.Introspection == nil {
		return claims, err
	}

	if err := v.introspect(ctx, token, claims); err != nil {
		return Claims{}, err
	}

	return claims, nil
}

func (v *Verifier) introspect(ctx context.Context, token string, claims Claims) error {
	in := v.cfg.Introspection
	unavailable := func(why string) error { return fmt.Errorf("%w: introspection: %s", ErrIssuerUnavailable, why) }

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, in.URL, strings.NewReader(url.Values{"token": {token}, "token_type_hint": {"access_token"}}.Encode()))
	if err != nil {
		return unavailable("bad request")
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(in.ResourceID), url.QueryEscape(in.Secret))
	// The answer is read from this address only: a redirect would send the credentials elsewhere.
	client := *v.cfg.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	resp, err := client.Do(req)
	if err != nil {
		return unavailable("no answer")
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return unavailable(fmt.Sprintf("status %d", resp.StatusCode))
	}

	var body struct {
		Active   bool   `json:"active"`
		Audience string `json:"aud"`
		Subject  string `json:"sub"`
		JTI      string `json:"jti"`
		ClientID string `json:"client_id"`
		Scope    string `json:"scope"`
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxIntrospectionBytes))
	if err != nil || json.Unmarshal(data, &body) != nil {
		return unavailable("unreadable answer")
	}

	if !body.Active {
		return invalid("the issuer says the token is not active")
	}
	// An active answer must be about this token: another one's would say yes to anything.
	if body.Audience != v.cfg.Audience || body.Subject != claims.Subject || body.JTI != claims.TokenID ||
		body.ClientID != claims.ClientID || body.Scope != strings.Join(claims.Scope, " ") {
		return unavailable("the answer is not about this token")
	}

	return nil
}

// key returns the public key of a kid, refreshing the key set when it is stale or the kid is new, but never more often than
// MinRefetch. A failed refresh keeps the old set, so an issuer outage does not stop the service.
func (v *Verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	now := v.cfg.Now()

	stale := v.keys == nil || now.Sub(v.fetchedAt) > v.cfg.MaxKeyAge
	if key, ok := v.keys[kid]; ok && !stale {
		return key, nil
	}

	fetched := false

	var fetchErr error
	if v.attemptedAt.IsZero() || now.Sub(v.attemptedAt) >= v.cfg.MinRefetch {
		fetchErr = v.refresh(ctx, now)
		fetched = fetchErr == nil
	}

	if key, ok := v.keys[kid]; ok {
		return key, nil
	}

	if !fetched {
		// Asked too recently, or the issuer did not answer: the key may exist, and a 503 is the honest answer.
		if fetchErr != nil {
			return nil, fmt.Errorf("%w: %w", ErrIssuerUnavailable, fetchErr)
		}

		return nil, ErrIssuerUnavailable
	}

	return nil, invalid("unknown key id")
}

func (v *Verifier) refresh(ctx context.Context, now time.Time) error {
	v.attemptedAt = now

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.JWKSURL, nil)
	if err != nil {
		return err
	}

	resp, err := v.cfg.Client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch the key set: %w", err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the key set answered %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil || len(data) > maxJWKSBytes {
		return errors.New("the key set is unreadable or too large")
	}

	keys, err := parseKeys(data)
	if err != nil {
		return err
	}

	v.keys, v.fetchedAt = keys, now

	return nil
}

// parseKeys keeps only RSA signing keys of at least 2048 bits with a kid. Anything else in the set is ignored, so an
// unrelated key cannot be used to verify access tokens.
func parseKeys(data []byte) (map[string]*rsa.PublicKey, error) {
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, errors.New("the key set is not valid JWKS")
	}

	keys := map[string]*rsa.PublicKey{}

	for _, k := range set.Keys {
		pub, ok := k.Key.(*rsa.PublicKey)
		if !ok || !k.IsPublic() || k.KeyID == "" || pub.N.BitLen() < minRSABits {
			continue
		}

		if k.Use != "" && k.Use != "sig" || k.Algorithm != "" && k.Algorithm != string(jose.RS256) {
			continue
		}

		keys[k.KeyID] = pub
	}

	if len(keys) == 0 {
		return nil, errors.New("the key set holds no usable key")
	}

	return keys, nil
}

// checkHeaderNames refuses a header that names anything but alg, typ and kid, or names one twice: jwk, jku, x5u, x5c and crit
// change how a key is found or what the rules are, and the service takes its keys only from the issuer's key set.
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

type contextKey struct{}

// FromContext returns the claims Require put in the request's context.
func FromContext(ctx context.Context) (Claims, bool) {
	c, ok := ctx.Value(contextKey{}).(Claims)
	return c, ok
}

// Require is middleware: it lets a request through only with a Bearer token that verifies and carries every one of the
// scopes the handler needs, and puts the claims in the request's context. The token is read from the Authorization header
// only; one in the query or the body would end up in logs. Answers follow RFC 6750: 401 for a missing or bad token, 403 with
// insufficient_scope for a good token that lacks a right, and 503 when the issuer's keys cannot be had.
func (v *Verifier) Require(scopes ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Vary", "Authorization")

			token, ok := bearer(r)
			if !ok {
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "unauthorized", http.StatusUnauthorized)

				return
			}

			claims, err := v.Check(r.Context(), token)
			switch {
			case errors.Is(err, ErrIssuerUnavailable):
				http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
				return
			case err != nil:
				w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)

				return
			}

			for _, scope := range scopes {
				if !claims.HasScope(scope) {
					w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="`+strings.Join(scopes, " ")+`"`)
					http.Error(w, "forbidden", http.StatusForbidden)

					return
				}
			}

			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, claims)))
		})
	}
}

// RequireUser is Require for an API that serves people: a token of a service identity is refused with 403 even though it is
// valid and carries the scopes, because it names no person. Use Require where a service is a legitimate caller.
func (v *Verifier) RequireUser(scopes ...string) func(http.Handler) http.Handler {
	inner := v.Require(scopes...)

	return func(next http.Handler) http.Handler {
		guarded := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if c, _ := FromContext(r.Context()); c.Service {
				w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope"`)
				http.Error(w, "forbidden", http.StatusForbidden)

				return
			}

			next.ServeHTTP(w, r)
		})

		return inner(guarded)
	}
}

// bearer returns the token of an Authorization: Bearer header. Exactly one header with one token passes.
func bearer(r *http.Request) (string, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}

	scheme, token, found := strings.Cut(values[0], " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" || len(token) > maxTokenBytes || strings.ContainsAny(token, " \t\r\n") {
		return "", false
	}

	return token, true
}
