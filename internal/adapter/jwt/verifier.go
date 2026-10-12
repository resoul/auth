package jwt

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"

	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/domain/session"
)

var _ port.AccessVerifier = (*Verifier)(nil)

// Verifier checks access tokens against a fixed set of trusted public keys. It
// never fetches keys named by the token, and an unknown kid is a refusal: there is
// no search through the other keys and no fallback to the active one.
type Verifier struct {
	keys     map[string]*ecdsa.PublicKey
	clock    port.Clock
	issuer   string
	audience string
	leeway   time.Duration
}

// NewVerifier builds a Verifier for one issuer and one audience. leeway is the
// allowed clock skew for exp, iat and nbf.
func NewVerifier(keys map[string]*ecdsa.PublicKey, clock port.Clock, issuer, audience string, leeway time.Duration) (*Verifier, error) {
	if len(keys) == 0 || clock == nil || issuer == "" || audience == "" || leeway < 0 {
		return nil, errors.New("new verifier: keys, a clock, an issuer, an audience and a non-negative leeway are required")
	}
	copied := make(map[string]*ecdsa.PublicKey, len(keys))
	for kid, key := range keys {
		if kid == "" || key == nil {
			return nil, errors.New("new verifier: every key needs a kid")
		}
		copied[kid] = key
	}
	return &Verifier{keys: copied, clock: clock, issuer: issuer, audience: audience, leeway: leeway}, nil
}

// allowedHeaders are the only protected header names a token may carry. Anything
// that could point at or embed a key (jwk, jku, x5u, x5c, x5t) or change the rules
// (crit) is refused, and so is a repeated name, which parsers resolve differently.
var allowedHeaders = map[string]bool{"alg": true, "typ": true, "kid": true}

func checkHeaderNames(token string) error { return checkHeaderNamesFor(token, invalid) }

// checkHeaderNamesFor is checkHeaderNames with the error each kind of token reports.
func checkHeaderNamesFor(token string, invalid func(string) error) error {
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
		if !allowedHeaders[name] {
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

func invalid(reason string) error {
	return fmt.Errorf("%w: %s", port.ErrInvalidAccessToken, reason)
}

// VerifyAccess checks the algorithm, type, key, signature, issuer, audience, time
// bounds and the presence and shape of every required claim.
func (v *Verifier) VerifyAccess(token string) (port.AccessClaims, error) {
	// Only the compact form is accepted; the library would also take JSON serializations.
	if strings.Count(token, ".") != 2 || strings.ContainsAny(token, " \t\r\n{}\"") {
		return port.AccessClaims{}, invalid("not a compact JWT")
	}
	parsed, err := josejwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return port.AccessClaims{}, invalid("unparsable or unsupported algorithm")
	}
	if len(parsed.Headers) != 1 {
		return port.AccessClaims{}, invalid("exactly one signature is required")
	}
	header := parsed.Headers[0]
	if header.KeyID == "" {
		return port.AccessClaims{}, invalid("missing kid")
	}
	if typ, _ := header.ExtraHeaders[jose.HeaderType].(string); typ != tokenType {
		return port.AccessClaims{}, invalid("wrong typ")
	}
	if err := checkHeaderNames(token); err != nil {
		return port.AccessClaims{}, err
	}
	key, ok := v.keys[header.KeyID]
	if !ok {
		return port.AccessClaims{}, invalid("unknown kid")
	}

	var std josejwt.Claims
	var priv privateClaims
	if err := parsed.Claims(key, &std, &priv); err != nil {
		return port.AccessClaims{}, invalid("bad signature or claims")
	}

	// The library validates fields that are present; presence is checked here.
	if std.Issuer == "" || std.Subject == "" || len(std.Audience) == 0 || std.Expiry == nil || std.IssuedAt == nil ||
		priv.SessionID == "" || priv.AuthTime == nil || len(priv.AMR) == 0 {
		return port.AccessClaims{}, invalid("a required claim is missing")
	}
	err = std.ValidateWithLeeway(josejwt.Expected{
		Issuer: v.issuer, AnyAudience: josejwt.Audience{v.audience}, Time: v.clock.Now(),
	}, v.leeway)
	if err != nil {
		return port.AccessClaims{}, invalid("issuer, audience or time check failed")
	}
	if !std.Expiry.Time().After(std.IssuedAt.Time()) {
		return port.AccessClaims{}, invalid("expiry is not after issue time")
	}

	userID, err := identity.ParseUserID(std.Subject)
	if err != nil {
		return port.AccessClaims{}, invalid("sub is not a user id")
	}
	sessionID, err := session.ParseID(priv.SessionID)
	if err != nil {
		return port.AccessClaims{}, invalid("sid is not a session id")
	}
	for _, method := range priv.AMR {
		if method == "" {
			return port.AccessClaims{}, invalid("empty amr entry")
		}
	}
	return port.AccessClaims{
		UserID: userID, SessionID: sessionID, AMR: priv.AMR,
		// NumericDate.Time returns the server's local zone; the port promises UTC.
		AuthTime: priv.AuthTime.Time().UTC(), IssuedAt: std.IssuedAt.Time().UTC(), ExpiresAt: std.Expiry.Time().UTC(),
	}, nil
}
