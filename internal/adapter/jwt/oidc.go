package jwt

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
)

var (
	_ port.OIDCSigner         = (*OIDCTokens)(nil)
	_ port.OIDCAccessVerifier = (*OIDCTokens)(nil)
)

// Types of the tokens this provider issues. An ID Token is a plain JWT; the access token follows RFC 9068.
const (
	idTokenType     = "JWT"
	logoutTokenType = "logout+jwt"
	logoutTokenTTL  = 2 * time.Minute
	logoutEvent     = "http://schemas.openid.net/event/backchannel-logout"
	oidcAccessType  = "at+jwt"
	jtiRandomBytes  = 16
	maxScopeLength  = 1024
	maxClaimLength  = 256
	maxAMREntries   = 8
	maxAudienceSize = 512
)

// OIDCTokens signs and verifies the RS256 tokens of the OpenID Provider with the ring's active key.
type OIDCTokens struct {
	ring      *RSARing
	idSigner  jose.Signer
	atSigner  jose.Signer
	lgSigner  jose.Signer
	clock     port.Clock
	issuer    string
	idTTL     time.Duration
	accessTTL time.Duration
	leeway    time.Duration
}

// NewOIDCTokens builds the signer and verifier. The issuer and positive lifetimes are required.
func NewOIDCTokens(ring *RSARing, clock port.Clock, issuer string, idTTL, accessTTL, leeway time.Duration) (*OIDCTokens, error) {
	if ring == nil || ring.private == nil || clock == nil {
		return nil, errors.New("new oidc tokens: a keyring with a private key and a clock are required")
	}

	if issuer == "" || idTTL <= 0 || accessTTL <= 0 || leeway < 0 {
		return nil, errors.New("new oidc tokens: an issuer, positive lifetimes and a non-negative leeway are required")
	}

	key := jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: ring.private, KeyID: ring.activeKID}}

	idSigner, err := jose.NewSigner(key, (&jose.SignerOptions{}).WithType(idTokenType))
	if err != nil {
		return nil, fmt.Errorf("new oidc tokens: %w", err)
	}

	atSigner, err := jose.NewSigner(key, (&jose.SignerOptions{}).WithType(oidcAccessType))
	if err != nil {
		return nil, fmt.Errorf("new oidc tokens: %w", err)
	}

	lgSigner, err := jose.NewSigner(key, (&jose.SignerOptions{}).WithType(logoutTokenType))
	if err != nil {
		return nil, fmt.Errorf("new oidc tokens: %w", err)
	}

	return &OIDCTokens{ring: ring, idSigner: idSigner, atSigner: atSigner, lgSigner: lgSigner, clock: clock, issuer: issuer, idTTL: idTTL, accessTTL: accessTTL, leeway: leeway}, nil
}

type idClaims struct {
	Nonce         string               `json:"nonce"`
	AuthTime      *josejwt.NumericDate `json:"auth_time"`
	AMR           []string             `json:"amr"`
	SessionID     string               `json:"sid"`
	Email         string               `json:"email,omitempty"`
	EmailVerified *bool                `json:"email_verified,omitempty"`
}

// SignIDToken issues an ID Token whose only audience is the client.
func (t *OIDCTokens) SignIDToken(c port.IDTokenClaims) (port.AccessToken, error) {
	if c.Subject.IsZero() || c.ClientID == "" || c.Nonce == "" || c.AuthTime.IsZero() || len(c.AMR) == 0 || c.SessionID == "" {
		return port.AccessToken{}, errors.New("sign id token: subject, client, nonce, auth time, methods and session are required")
	}

	now := t.clock.Now()
	expiry := josejwt.NewNumericDate(now.Add(t.idTTL))

	extra := idClaims{Nonce: c.Nonce, AuthTime: josejwt.NewNumericDate(c.AuthTime), AMR: c.AMR, SessionID: c.SessionID}
	if c.IncludeEmail {
		verified := c.EmailVerified
		extra.Email, extra.EmailVerified = c.Email, &verified
	}

	value, err := josejwt.Signed(t.idSigner).
		Claims(josejwt.Claims{
			Issuer: t.issuer, Subject: c.Subject.String(), Audience: josejwt.Audience{c.ClientID},
			IssuedAt: josejwt.NewNumericDate(now), Expiry: expiry,
		}).
		Claims(extra).
		Serialize()
	if err != nil {
		return port.AccessToken{}, fmt.Errorf("sign id token: %w", err)
	}

	return port.AccessToken{Value: value, ExpiresAt: expiry.Time().UTC()}, nil
}

type accessClaims struct {
	ClientID  string               `json:"client_id"`
	Scope     string               `json:"scope"`
	SessionID string               `json:"sid,omitempty"`
	GrantID   string               `json:"grant_id,omitempty"`
	AuthTime  *josejwt.NumericDate `json:"auth_time,omitempty"`
}

// SignOIDCAccessToken issues an access token for exactly one audience (RFC 9068) and returns the claims it made,
// the jti included, for the audit trail.
func (t *OIDCTokens) SignOIDCAccessToken(c port.OIDCAccessClaims) (port.AccessToken, port.OIDCAccessClaims, error) {
	if c.Subject.IsZero() || c.ClientID == "" || c.Audience == "" || len(c.Scope) == 0 || c.SessionID == "" || c.GrantID == "" || c.AuthTime.IsZero() {
		return port.AccessToken{}, port.OIDCAccessClaims{}, errors.New("sign oidc access token: subject, client, audience, scope, session, grant and auth time are required")
	}

	raw := make([]byte, jtiRandomBytes)
	if _, err := rand.Read(raw); err != nil {
		return port.AccessToken{}, port.OIDCAccessClaims{}, fmt.Errorf("sign oidc access token: %w", err)
	}

	jti := base64.RawURLEncoding.EncodeToString(raw)
	now := t.clock.Now()
	expiry := josejwt.NewNumericDate(now.Add(t.accessTTL))

	value, err := josejwt.Signed(t.atSigner).
		Claims(josejwt.Claims{
			Issuer: t.issuer, Subject: c.Subject.String(), Audience: josejwt.Audience{c.Audience},
			IssuedAt: josejwt.NewNumericDate(now), Expiry: expiry, ID: jti,
		}).
		Claims(accessClaims{ClientID: c.ClientID, Scope: strings.Join(c.Scope, " "), SessionID: c.SessionID, GrantID: c.GrantID, AuthTime: josejwt.NewNumericDate(c.AuthTime)}).
		Serialize()
	if err != nil {
		return port.AccessToken{}, port.OIDCAccessClaims{}, fmt.Errorf("sign oidc access token: %w", err)
	}

	c.JTI, c.IssuedAt, c.ExpiresAt = jti, now.UTC(), expiry.Time().UTC()

	return port.AccessToken{Value: value, ExpiresAt: c.ExpiresAt}, c, nil
}

func invalidOIDC(reason string) error {
	return fmt.Errorf("%w: %s", port.ErrInvalidOIDCToken, reason)
}

// parseAccess checks what every access token of this provider shares: RS256 only, the at+jwt type, a key of the ring, this
// issuer, exactly the audience asked for, one audience, and the time bounds. The header may name only alg, typ and kid:
// nothing in a token points at or carries a key. What a kind of token must carry is for its own verifier.
func (t *OIDCTokens) parseAccess(token, audience string) (josejwt.Claims, accessClaims, error) {
	var (
		std  josejwt.Claims
		priv accessClaims
	)
	if audience == "" || len(audience) > maxAudienceSize {
		return std, priv, invalidOIDC("no audience to check against")
	}

	if strings.Count(token, ".") != 2 || strings.ContainsAny(token, " \t\r\n{}\"") {
		return std, priv, invalidOIDC("not a compact JWT")
	}

	parsed, err := josejwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return std, priv, invalidOIDC("unparsable or unsupported algorithm")
	}

	if len(parsed.Headers) != 1 {
		return std, priv, invalidOIDC("exactly one signature is required")
	}

	header := parsed.Headers[0]
	if header.KeyID == "" {
		return std, priv, invalidOIDC("missing kid")
	}

	if typ, _ := header.ExtraHeaders[jose.HeaderType].(string); typ != oidcAccessType {
		return std, priv, invalidOIDC("wrong typ")
	}

	if err := checkHeaderNamesFor(token, invalidOIDC); err != nil {
		return std, priv, err
	}

	key, ok := t.ring.public[header.KeyID]
	if !ok {
		return std, priv, invalidOIDC("unknown kid")
	}

	if err := parsed.Claims(key, &std, &priv); err != nil {
		return std, priv, invalidOIDC("bad signature or claims")
	}

	if std.Issuer == "" || std.Subject == "" || len(std.Audience) == 0 || std.Expiry == nil || std.IssuedAt == nil || std.ID == "" ||
		priv.ClientID == "" || priv.Scope == "" {
		return std, priv, invalidOIDC("a required claim is missing")
	}

	if len(priv.Scope) > maxScopeLength || len(priv.ClientID) > maxClaimLength || len(std.ID) > maxClaimLength {
		return std, priv, invalidOIDC("a claim is too long")
	}

	if len(std.Audience) != 1 {
		return std, priv, invalidOIDC("exactly one audience is required")
	}

	err = std.ValidateWithLeeway(josejwt.Expected{Issuer: t.issuer, AnyAudience: josejwt.Audience{audience}, Time: t.clock.Now()}, t.leeway)
	if err != nil {
		return std, priv, invalidOIDC("issuer, audience or time check failed")
	}

	if !std.Expiry.Time().After(std.IssuedAt.Time()) {
		return std, priv, invalidOIDC("expiry is not after issue time")
	}

	return std, priv, nil
}

// VerifyOIDCAccess checks the access token of a user presented to this provider: what parseAccess checks, and the claims of
// a sign-in (sid, grant, auth_time) with a user's identifier as the subject.
func (t *OIDCTokens) VerifyOIDCAccess(token, audience string) (port.OIDCAccessClaims, error) {
	std, priv, err := t.parseAccess(token, audience)
	if err != nil {
		return port.OIDCAccessClaims{}, err
	}

	if priv.SessionID == "" || priv.GrantID == "" || priv.AuthTime == nil {
		return port.OIDCAccessClaims{}, invalidOIDC("a required claim is missing")
	}

	userID, err := identity.ParseUserID(std.Subject)
	if err != nil {
		return port.OIDCAccessClaims{}, invalidOIDC("sub is not a user id")
	}

	return port.OIDCAccessClaims{
		Subject: userID, ClientID: priv.ClientID, Audience: audience, Scope: strings.Fields(priv.Scope),
		SessionID: priv.SessionID, GrantID: priv.GrantID, AuthTime: priv.AuthTime.Time().UTC(), JTI: std.ID,
		IssuedAt: std.IssuedAt.Time().UTC(), ExpiresAt: std.Expiry.Time().UTC(),
	}, nil
}

// SignServiceToken issues the access token of a service identity: the client is the subject, and the token carries no
// sid, grant or auth_time, so it cannot pass for a user's. The type, issuer, audience and lifetime are those of any access
// token of the provider.
func (t *OIDCTokens) SignServiceToken(c port.ServiceAccessClaims) (port.AccessToken, port.ServiceAccessClaims, error) {
	if c.ClientID == "" || c.Audience == "" || len(c.Scope) == 0 {
		return port.AccessToken{}, port.ServiceAccessClaims{}, errors.New("sign service token: client, audience and scope are required")
	}

	raw := make([]byte, jtiRandomBytes)
	if _, err := rand.Read(raw); err != nil {
		return port.AccessToken{}, port.ServiceAccessClaims{}, fmt.Errorf("sign service token: %w", err)
	}

	jti := base64.RawURLEncoding.EncodeToString(raw)
	now := t.clock.Now()
	expiry := josejwt.NewNumericDate(now.Add(t.accessTTL))

	value, err := josejwt.Signed(t.atSigner).
		Claims(josejwt.Claims{
			Issuer: t.issuer, Subject: c.ClientID, Audience: josejwt.Audience{c.Audience},
			IssuedAt: josejwt.NewNumericDate(now), Expiry: expiry, ID: jti,
		}).
		Claims(accessClaims{ClientID: c.ClientID, Scope: strings.Join(c.Scope, " ")}).
		Serialize()
	if err != nil {
		return port.AccessToken{}, port.ServiceAccessClaims{}, fmt.Errorf("sign service token: %w", err)
	}

	c.JTI, c.IssuedAt, c.ExpiresAt = jti, now.UTC(), expiry.Time().UTC()

	return port.AccessToken{Value: value, ExpiresAt: c.ExpiresAt}, c, nil
}

// VerifyServiceAccess checks the access token of a service: what parseAccess checks, a subject equal to the client_id, and
// none of the claims of a sign-in.
func (t *OIDCTokens) VerifyServiceAccess(token, audience string) (port.ServiceAccessClaims, error) {
	std, priv, err := t.parseAccess(token, audience)
	if err != nil {
		return port.ServiceAccessClaims{}, err
	}

	if std.Subject != priv.ClientID || priv.SessionID != "" || priv.GrantID != "" || priv.AuthTime != nil {
		return port.ServiceAccessClaims{}, invalidOIDC("not the token of a service")
	}

	return port.ServiceAccessClaims{
		ClientID: priv.ClientID, Audience: audience, Scope: strings.Fields(priv.Scope), JTI: std.ID,
		IssuedAt: std.IssuedAt.Time().UTC(), ExpiresAt: std.Expiry.Time().UTC(),
	}, nil
}

type logoutClaims struct {
	Events    map[string]struct{} `json:"events"`
	SessionID string              `json:"sid"`
}

// SignLogoutToken issues the token of a back-channel logout notice (OpenID Connect Back-Channel Logout 1.0): the type
// logout+jwt, the audience of the one client, the sign-in's sid, the backchannel-logout event, and no nonce, so it can
// never pass for an ID token. Its life is short; a notice delivered again gets a fresh token with the same jti.
func (t *OIDCTokens) SignLogoutToken(c port.LogoutClaims) (port.AccessToken, error) {
	if c.Subject.IsZero() || c.ClientID == "" || c.SessionID == "" || c.JTI == "" {
		return port.AccessToken{}, errors.New("sign logout token: subject, client, session and jti are required")
	}

	now := t.clock.Now()
	expiry := josejwt.NewNumericDate(now.Add(logoutTokenTTL))

	value, err := josejwt.Signed(t.lgSigner).
		Claims(josejwt.Claims{
			Issuer: t.issuer, Subject: c.Subject.String(), Audience: josejwt.Audience{c.ClientID},
			IssuedAt: josejwt.NewNumericDate(now), Expiry: expiry, ID: c.JTI,
		}).
		Claims(logoutClaims{Events: map[string]struct{}{logoutEvent: {}}, SessionID: c.SessionID}).
		Serialize()
	if err != nil {
		return port.AccessToken{}, fmt.Errorf("sign logout token: %w", err)
	}

	return port.AccessToken{Value: value, ExpiresAt: expiry.Time().UTC()}, nil
}

// VerifyIDTokenHint checks that an ID token is one this provider issued: RS256, the JWT type, a key of the ring, this
// issuer and exactly one audience. The expiry is not checked, because a client names the sign-in to end with the last ID
// token it holds, and that one has usually expired. A token of another type (an access token, a logout token) is refused.
func (t *OIDCTokens) VerifyIDTokenHint(token string) (port.IDTokenHint, error) {
	if strings.Count(token, ".") != 2 || strings.ContainsAny(token, " \t\r\n{}\"") {
		return port.IDTokenHint{}, invalidOIDC("not a compact JWT")
	}

	parsed, err := josejwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return port.IDTokenHint{}, invalidOIDC("unparsable or unsupported algorithm")
	}

	if len(parsed.Headers) != 1 {
		return port.IDTokenHint{}, invalidOIDC("exactly one signature is required")
	}

	header := parsed.Headers[0]
	if header.KeyID == "" {
		return port.IDTokenHint{}, invalidOIDC("missing kid")
	}

	if typ, _ := header.ExtraHeaders[jose.HeaderType].(string); typ != idTokenType {
		return port.IDTokenHint{}, invalidOIDC("wrong typ")
	}

	if err := checkHeaderNamesFor(token, invalidOIDC); err != nil {
		return port.IDTokenHint{}, err
	}

	key, ok := t.ring.public[header.KeyID]
	if !ok {
		return port.IDTokenHint{}, invalidOIDC("unknown kid")
	}

	var (
		std  josejwt.Claims
		priv idClaims
	)
	if err := parsed.Claims(key, &std, &priv); err != nil {
		return port.IDTokenHint{}, invalidOIDC("bad signature or claims")
	}

	if std.Issuer != t.issuer || std.Subject == "" || len(std.Audience) != 1 || std.Audience[0] == "" || priv.SessionID == "" || priv.Nonce == "" {
		return port.IDTokenHint{}, invalidOIDC("not an ID token of this issuer")
	}

	if len(std.Audience[0]) > maxClaimLength || len(priv.SessionID) > maxClaimLength {
		return port.IDTokenHint{}, invalidOIDC("a claim is too long")
	}

	userID, err := identity.ParseUserID(std.Subject)
	if err != nil {
		return port.IDTokenHint{}, invalidOIDC("sub is not a user id")
	}

	return port.IDTokenHint{Subject: userID, ClientID: std.Audience[0], SessionID: priv.SessionID}, nil
}
