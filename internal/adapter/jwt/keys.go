package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/go-jose/go-jose/v4"

	"go.airlance.org/auth/internal/application/port"
)

var _ port.JWKSPublisher = (*Ring)(nil)

const maxKeyFileSize = 8 * 1024

type Ring struct {
	activeKID string
	private   *ecdsa.PrivateKey
	public    map[string]*ecdsa.PublicKey
}

func LoadRing(activeKID string, keyFiles map[string]string) (*Ring, error) {
	if len(keyFiles) == 0 {
		return nil, errors.New("jwt keyring: no keys")
	}

	ring := &Ring{activeKID: activeKID, public: make(map[string]*ecdsa.PublicKey, len(keyFiles))}
	for kid, path := range keyFiles {
		if kid == "" {
			return nil, errors.New("jwt keyring: empty kid")
		}

		pub, priv, err := readKeyFile(path)
		if err != nil {
			return nil, fmt.Errorf("jwt key %q: %w", kid, err)
		}

		ring.public[kid] = pub
		if kid == activeKID {
			ring.private = priv
		}
	}

	if _, ok := ring.public[activeKID]; !ok {
		return nil, fmt.Errorf("jwt keyring: active kid %q is not in keys", activeKID)
	}

	if ring.private == nil {
		return nil, fmt.Errorf("jwt keyring: active kid %q has no private key", activeKID)
	}

	return ring, nil
}

func readKeyFile(path string) (*ecdsa.PublicKey, *ecdsa.PrivateKey, error) {
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

	pub, priv, err := parsePEM(data)
	if err != nil {
		return nil, nil, fmt.Errorf("key file %s: %w", path, err)
	}

	return pub, priv, nil
}

func parsePEM(data []byte) (*ecdsa.PublicKey, *ecdsa.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, nil, errors.New("no PEM block")
	}

	if len(trimSpace(rest)) != 0 {
		return nil, nil, errors.New("unexpected data after the PEM block")
	}

	switch block.Type {
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, errors.New("invalid PKCS#8 private key")
		}

		priv, ok := parsed.(*ecdsa.PrivateKey)
		if !ok || priv.Curve != elliptic.P256() {
			return nil, nil, errors.New("key must be ECDSA P-256")
		}

		return &priv.PublicKey, priv, nil
	case "PUBLIC KEY":
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, nil, errors.New("invalid PKIX public key")
		}

		pub, ok := parsed.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return nil, nil, errors.New("key must be ECDSA P-256")
		}

		return pub, nil, nil
	}

	return nil, nil, fmt.Errorf("unsupported PEM type %q: want PRIVATE KEY (PKCS#8) or PUBLIC KEY (PKIX)", block.Type)
}

func trimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && (b[start] == ' ' || b[start] == '\n' || b[start] == '\r' || b[start] == '\t') {
		start++
	}

	for end > start && (b[end-1] == ' ' || b[end-1] == '\n' || b[end-1] == '\r' || b[end-1] == '\t') {
		end--
	}

	return b[start:end]
}

func (r *Ring) ActiveKID() string {
	return r.activeKID
}

func (r *Ring) KIDs() []string {
	kids := make([]string, 0, len(r.public))
	for kid := range r.public {
		kids = append(kids, kid)
	}

	sort.Strings(kids)

	return kids
}

func (r *Ring) PublicKeys() map[string]*ecdsa.PublicKey {
	out := make(map[string]*ecdsa.PublicKey, len(r.public))
	for kid, key := range r.public {
		out[kid] = key
	}

	return out
}

func (r *Ring) JWKS() ([]byte, error) {
	set := jose.JSONWebKeySet{}
	for _, kid := range r.KIDs() {
		set.Keys = append(set.Keys, jose.JSONWebKey{
			Key: r.public[kid], KeyID: kid, Algorithm: string(jose.ES256), Use: "sig",
		})
	}

	data, err := json.Marshal(set)
	if err != nil {
		return nil, fmt.Errorf("encode jwks: %w", err)
	}

	return data, nil
}

func (r *Ring) String() string {
	return fmt.Sprintf("jwt keyring (active %q, %d keys)", r.activeKID, len(r.public))
}

func (r *Ring) GoString() string {
	return r.String()
}

func ParseJWKS(data []byte) (map[string]*ecdsa.PublicKey, error) {
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, errors.New("jwks: invalid JSON key set")
	}

	if len(set.Keys) == 0 {
		return nil, errors.New("jwks: no keys")
	}

	keys := make(map[string]*ecdsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.KeyID == "" {
			return nil, errors.New("jwks: key without kid")
		}

		if _, dup := keys[k.KeyID]; dup {
			return nil, fmt.Errorf("jwks: duplicate kid %q", k.KeyID)
		}

		if !k.IsPublic() {
			return nil, fmt.Errorf("jwks: kid %q is not a public key", k.KeyID)
		}

		if (k.Use != "" && k.Use != "sig") || (k.Algorithm != "" && k.Algorithm != string(jose.ES256)) {
			return nil, fmt.Errorf("jwks: kid %q is not an ES256 signature key", k.KeyID)
		}

		pub, ok := k.Key.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return nil, fmt.Errorf("jwks: kid %q must be ECDSA P-256", k.KeyID)
		}

		keys[k.KeyID] = pub
	}

	return keys, nil
}
