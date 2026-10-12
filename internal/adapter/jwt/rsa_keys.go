package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/go-jose/go-jose/v4"
)

// Bounds of an RSA signing key. Below 2048 bits the key is too weak to sign with; the upper bound keeps a
// misplaced file from making every verification slow.
const (
	minRSABits = 2048
	maxRSABits = 8192
)

// RSARing holds the RS256 keys of the OpenID Provider by kid: the active private key and the public keys of every
// kid that may still sign valid tokens. It is separate from Ring on purpose: the ES256 keys of the /v1 API and the
// RS256 keys of OIDC publish in different key sets, so adding OIDC cannot change what existing verifiers see.
type RSARing struct {
	activeKID string
	private   *rsa.PrivateKey
	public    map[string]*rsa.PublicKey
}

// LoadRSARing reads every key file (kid to path) and builds the ring. A file holds one PEM block: PKCS#8
// "PRIVATE KEY" or PKIX "PUBLIC KEY" of an RSA key of 2048 to 8192 bits. The active kid must have a private key.
// Errors name the kid and path, never contents.
func LoadRSARing(activeKID string, keyFiles map[string]string) (*RSARing, error) {
	if len(keyFiles) == 0 {
		return nil, errors.New("oidc keyring: no keys")
	}
	ring := &RSARing{activeKID: activeKID, public: make(map[string]*rsa.PublicKey, len(keyFiles))}
	for kid, path := range keyFiles {
		if kid == "" {
			return nil, errors.New("oidc keyring: empty kid")
		}
		pub, priv, err := readRSAKeyFile(path)
		if err != nil {
			return nil, fmt.Errorf("oidc key %q: %w", kid, err)
		}
		ring.public[kid] = pub
		if kid == activeKID {
			ring.private = priv
		}
	}
	if _, ok := ring.public[activeKID]; !ok {
		return nil, fmt.Errorf("oidc keyring: active kid %q is not in keys", activeKID)
	}
	if ring.private == nil {
		return nil, fmt.Errorf("oidc keyring: active kid %q has no private key", activeKID)
	}
	return ring, nil
}

func readRSAKeyFile(path string) (*rsa.PublicKey, *rsa.PrivateKey, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the path comes from the operator's keyring file, not request input
	if err != nil {
		return nil, nil, fmt.Errorf("open key file: %w", err)
	}
	defer func() { _ = f.Close() }() // read-only file: a close error loses nothing
	info, err := f.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("stat key file %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("key file %s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxKeyFileSize+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read key file %s: %w", path, err)
	}
	if len(data) > maxKeyFileSize {
		return nil, nil, fmt.Errorf("key file %s is too large", path)
	}
	pub, priv, err := parseRSAPEM(data)
	if err != nil {
		return nil, nil, fmt.Errorf("key file %s: %w", path, err)
	}
	return pub, priv, nil
}

// parseRSAPEM accepts exactly one block. The messages never include the data.
func parseRSAPEM(data []byte) (*rsa.PublicKey, *rsa.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, nil, errors.New("no PEM block")
	}
	if len(trimSpace(rest)) != 0 {
		return nil, nil, errors.New("unexpected data after the PEM block")
	}
	var pub *rsa.PublicKey
	var priv *rsa.PrivateKey
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, errors.New("invalid PKCS#8 private key")
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, errors.New("key must be RSA")
		}
		priv, pub = key, &key.PublicKey
	case "PUBLIC KEY":
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, nil, errors.New("invalid PKIX public key")
		}
		key, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return nil, nil, errors.New("key must be RSA")
		}
		pub = key
	default:
		return nil, nil, fmt.Errorf("unsupported PEM type %q: want PRIVATE KEY (PKCS#8) or PUBLIC KEY (PKIX)", block.Type)
	}
	if bits := pub.N.BitLen(); bits < minRSABits || bits > maxRSABits {
		return nil, nil, fmt.Errorf("RSA key must be %d to %d bits, not %d", minRSABits, maxRSABits, bits)
	}
	return pub, priv, nil
}

// ActiveKID returns the kid that signs new tokens.
func (r *RSARing) ActiveKID() string { return r.activeKID }

// KIDs returns every kid in sorted order.
func (r *RSARing) KIDs() []string {
	kids := make([]string, 0, len(r.public))
	for kid := range r.public {
		kids = append(kids, kid)
	}
	sort.Strings(kids)
	return kids
}

// PublicKeys returns a copy of the kid to public key map, for a verifier.
func (r *RSARing) PublicKeys() map[string]*rsa.PublicKey {
	out := make(map[string]*rsa.PublicKey, len(r.public))
	for kid, key := range r.public {
		out[kid] = key
	}
	return out
}

// JWKS returns the public key set as JSON, ordered by kid so a restart publishes the same bytes. Private
// material is never included.
func (r *RSARing) JWKS() ([]byte, error) {
	set := jose.JSONWebKeySet{}
	for _, kid := range r.KIDs() {
		set.Keys = append(set.Keys, jose.JSONWebKey{Key: r.public[kid], KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"})
	}
	data, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("encode jwks: %w", err)
	}
	return data, nil
}

// String and GoString keep key material out of %v and %#v output.
func (r *RSARing) String() string {
	return fmt.Sprintf("oidc keyring (active %q, %d keys)", r.activeKID, len(r.public))
}

// GoString implements fmt.GoStringer.
func (r *RSARing) GoString() string { return r.String() }
