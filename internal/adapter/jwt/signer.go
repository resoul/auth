package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"

	"go.airlance.org/auth/internal/application/port"
)

var _ port.AccessSigner = (*Signer)(nil)

const tokenType = "at+jwt"

type privateClaims struct {
	SessionID string               `json:"sid"`
	AuthTime  *josejwt.NumericDate `json:"auth_time"`
	AMR       []string             `json:"amr"`
}

type Signer struct {
	signer   jose.Signer
	clock    port.Clock
	issuer   string
	audience string
	ttl      time.Duration
}

func NewSigner(ring *Ring, clock port.Clock, issuer, audience string, ttl time.Duration) (*Signer, error) {
	if ring == nil || ring.private == nil || clock == nil {
		return nil, errors.New("new signer: a keyring with a private key and a clock are required")
	}

	if issuer == "" || audience == "" || ttl <= 0 {
		return nil, errors.New("new signer: issuer, audience and a positive ttl are required")
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: ring.private, KeyID: ring.activeKID}},
		(&jose.SignerOptions{}).WithType(tokenType),
	)
	if err != nil {
		return nil, fmt.Errorf("new signer: %w", err)
	}

	return &Signer{signer: signer, clock: clock, issuer: issuer, audience: audience, ttl: ttl}, nil
}

func (s *Signer) SignAccess(c port.AccessClaims) (port.AccessToken, error) {
	if c.UserID.IsZero() || c.SessionID.IsZero() || c.AuthTime.IsZero() || len(c.AMR) == 0 {
		return port.AccessToken{}, errors.New("sign access: user, session, auth time and methods are required")
	}

	now := s.clock.Now()
	expiry := josejwt.NewNumericDate(now.Add(s.ttl))

	value, err := josejwt.Signed(s.signer).
		Claims(josejwt.Claims{
			Issuer: s.issuer, Subject: c.UserID.String(), Audience: josejwt.Audience{s.audience},
			IssuedAt: josejwt.NewNumericDate(now), Expiry: expiry,
		}).
		Claims(privateClaims{SessionID: c.SessionID.String(), AuthTime: josejwt.NewNumericDate(c.AuthTime), AMR: c.AMR}).
		Serialize()
	if err != nil {
		return port.AccessToken{}, fmt.Errorf("sign access: %w", err)
	}

	return port.AccessToken{Value: value, ExpiresAt: expiry.Time().UTC()}, nil
}
