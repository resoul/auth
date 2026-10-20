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

const (
	minRSABits = 2048
	maxRSABits = 8192
)

type RSARing struct {
	activeKID string
	private   *rsa.PrivateKey
	public    map[string]*rsa.PublicKey
}

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

func parseRSAPEM(data []byte) (*rsa.PublicKey, *rsa.PrivateKey, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, nil, errors.New("no PEM block")
	}

	if len(trimSpace(rest)) != 0 {
		return nil, nil, errors.New("unexpected data after the PEM block")
	}

	var (
		pub  *rsa.PublicKey
		priv *rsa.PrivateKey
	)

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

func (r *RSARing) ActiveKID() string {
	return r.activeKID
}

func (r *RSARing) KIDs() []string {
	kids := make([]string, 0, len(r.public))
	for kid := range r.public {
		kids = append(kids, kid)
	}

	sort.Strings(kids)

	return kids
}

func (r *RSARing) PublicKeys() map[string]*rsa.PublicKey {
	out := make(map[string]*rsa.PublicKey, len(r.public))
	for kid, key := range r.public {
		out[kid] = key
	}

	return out
}

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

func (r *RSARing) String() string {
	return fmt.Sprintf("oidc keyring (active %q, %d keys)", r.activeKID, len(r.public))
}

func (r *RSARing) GoString() string {
	return r.String()
}
