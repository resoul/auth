package bff

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// ErrKeysUnavailable means a token could not be checked because the key it names could not be had now: the issuer cannot be
// reached, or was asked too recently to be asked again. It is not a verdict on the token, which may be a good one signed with a
// key just published; the caller answers "try again", never "invalid".
var ErrKeysUnavailable = errors.New("bff: the issuer's keys are not available now")

// maxJWKSBytes bounds the key set an issuer may send.
const maxJWKSBytes = 64 << 10

// keySet is the issuer's key set as an application should hold it: fetched from the one address the discovery document
// named, with a time limit and a size limit; kept for a while; refetched when it is stale, or when a token names a key that
// is not in it, but never more often than minRefetch, so a client that sends tokens with invented key ids cannot make the
// application call the issuer all day; and kept as it was when the issuer cannot be reached, so an outage does not sign
// everyone out. It satisfies the KeySet of go-oidc, which does the rest of the checking of a token.
type keySet struct {
	url        string
	client     *http.Client
	now        func() time.Time
	maxAge     time.Duration
	minRefetch time.Duration

	mu          sync.Mutex
	keys        map[string]jose.JSONWebKey
	fetchedAt   time.Time
	attemptedAt time.Time
}

// VerifySignature implements oidc.KeySet: RS256 only, one signature, a key id of the set.
func (k *keySet) VerifySignature(ctx context.Context, token string) ([]byte, error) {
	sig, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil || len(sig.Signatures) != 1 {
		return nil, errors.New("bff: not a token signed with RS256")
	}
	kid := sig.Signatures[0].Header.KeyID
	if kid == "" {
		return nil, errors.New("bff: the token names no key")
	}
	key, err := k.key(ctx, kid)
	if err != nil {
		return nil, err
	}
	payload, err := sig.Verify(key.Key)
	if err != nil {
		return nil, errors.New("bff: the signature does not verify")
	}
	return payload, nil
}

func (k *keySet) key(ctx context.Context, kid string) (jose.JSONWebKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	now := k.now()
	stale := k.keys == nil || now.Sub(k.fetchedAt) > k.maxAge
	if key, ok := k.keys[kid]; ok && !stale {
		return key, nil
	}
	fetched := false
	if k.attemptedAt.IsZero() || now.Sub(k.attemptedAt) >= k.minRefetch {
		fetched = k.refresh(ctx, now) == nil
	}
	if key, ok := k.keys[kid]; ok {
		return key, nil
	}
	if !fetched {
		// Asked too recently, or the issuer did not answer: the key may exist, so this is not a refusal.
		return jose.JSONWebKey{}, ErrKeysUnavailable
	}
	return jose.JSONWebKey{}, errors.New("bff: the token names a key the issuer does not publish")
}

func (k *keySet) refresh(ctx context.Context, now time.Time) error {
	k.attemptedAt = now
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return err
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("bff: fetch the key set: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bff: the key set answered %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil || len(data) > maxJWKSBytes {
		return errors.New("bff: the key set is unreadable or too large")
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(data, &set); err != nil {
		return errors.New("bff: the key set is not valid JWKS")
	}
	keys := map[string]jose.JSONWebKey{}
	for _, key := range set.Keys {
		if key.KeyID == "" || !key.IsPublic() || key.Use != "" && key.Use != "sig" || key.Algorithm != "" && key.Algorithm != string(jose.RS256) {
			continue
		}
		keys[key.KeyID] = key
	}
	if len(keys) == 0 {
		return errors.New("bff: the key set holds no usable key")
	}
	k.keys, k.fetchedAt = keys, now
	return nil
}
