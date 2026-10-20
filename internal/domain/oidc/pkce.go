package oidc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"regexp"
)

// A S256 challenge is the unpadded base64url of a SHA-256: exactly 43 characters.
var challengeShape = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// A verifier is 43 to 128 characters of the unreserved set (RFC 7636 section 4.1).
var verifierShape = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

// ValidChallenge reports whether s can be the S256 challenge of some verifier.
func ValidChallenge(s string) bool { return challengeShape.MatchString(s) }

// VerifyPKCE reports whether the verifier produces the challenge, comparing in constant time. Only S256 exists:
// there is no plain method to fall back to.
func VerifyPKCE(challenge, verifier string) bool {
	if !ValidChallenge(challenge) || !verifierShape.MatchString(verifier) {
		return false
	}

	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])

	return subtle.ConstantTimeCompare([]byte(want), []byte(challenge)) == 1
}

// Challenge returns the S256 challenge of a verifier, for clients and tests.
func Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
