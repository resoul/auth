package bootstrap

import (
	"fmt"
	"time"

	"go.airlance.org/auth/internal/adapter/clock"
	"go.airlance.org/auth/internal/adapter/jwt"
	"go.airlance.org/auth/internal/config"
)

// tokenLeeway is the clock skew tolerated when verifying exp, iat and nbf.
const tokenLeeway = 30 * time.Second

// jwtParts are the access token components built from the jwt_signing keyring.
type jwtParts struct {
	ring     *jwt.Ring
	signer   *jwt.Signer
	verifier *jwt.Verifier
}

// newJWT builds the signer, the verifier and the JWKS source. It returns nil when
// the jwt_signing purpose is not configured; a configured purpose must load
// completely and publish a valid key set.
func newJWT(cfg config.Config) (*jwtParts, error) {
	if cfg.Keyring == nil || cfg.Keyring.JWTSigning == nil {
		return nil, nil
	}

	set := cfg.Keyring.JWTSigning

	files := make(map[string]string, len(set.Keys))
	for kid, ref := range set.Keys {
		files[kid] = ref.KeyFile
	}

	ring, err := jwt.LoadRing(set.ActiveKID, files)
	if err != nil {
		return nil, fmt.Errorf("load jwt keyring: %w", err)
	}

	signer, err := jwt.NewSigner(ring, clock.System{}, cfg.JWT.Issuer, cfg.JWT.Audience, cfg.JWT.AccessTTL)
	if err != nil {
		return nil, fmt.Errorf("create access token signer: %w", err)
	}

	verifier, err := jwt.NewVerifier(ring.PublicKeys(), clock.System{}, cfg.JWT.Issuer, cfg.JWT.Audience, tokenLeeway)
	if err != nil {
		return nil, fmt.Errorf("create access token verifier: %w", err)
	}

	if _, err := ring.JWKS(); err != nil {
		return nil, fmt.Errorf("publish jwks: %w", err)
	}

	return &jwtParts{ring: ring, signer: signer, verifier: verifier}, nil
}
