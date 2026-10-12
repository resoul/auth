package bff

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Vault seals the tokens a backend keeps for its sessions, so a copy of the session table (a backup, a replica, a leaked
// dump) holds nothing that can be presented to the provider or to an API. It is AES-256-GCM with a keyring: new values are
// sealed under the active key, and values sealed under an older one stay readable until that key is dropped, which is how a
// key is rotated without signing everyone out. The identity of the row is part of what is authenticated, so a sealed value
// copied into another session does not open.
type Vault struct {
	active string
	keys   map[string]cipher.AEAD
}

// NewVault builds a vault from 32-byte keys by identifier. Keep the keys outside the database that holds the sessions: a
// secret manager, or an environment of the service; and to rotate, add the new key, make it active, wait for the sessions
// that were sealed under the old one to end (or re-seal them), then remove the old one.
func NewVault(active string, keys map[string][]byte) (*Vault, error) {
	if _, ok := keys[active]; !ok {
		return nil, errors.New("bff: the active key is not in the keyring")
	}
	v := &Vault{active: active, keys: make(map[string]cipher.AEAD, len(keys))}
	for kid, key := range keys {
		if kid == "" || strings.Contains(kid, ".") || len(key) != 32 {
			return nil, errors.New("bff: a vault key needs a name without a dot and 32 bytes")
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		v.keys[kid] = gcm
	}
	return v, nil
}

// Seal encrypts plaintext for the row named by binding.
func (v *Vault) Seal(plaintext, binding string) (string, error) {
	gcm := v.keys[v.active]
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("bff: seal: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), []byte(binding))
	return v.active + "." + base64.RawURLEncoding.EncodeToString(sealed), nil
}

// Open decrypts a value sealed for the same binding.
func (v *Vault) Open(sealed, binding string) (string, error) {
	kid, body, ok := strings.Cut(sealed, ".")
	gcm := v.keys[kid]
	if !ok || gcm == nil {
		return "", errors.New("bff: the sealed value is not readable")
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil || len(raw) < gcm.NonceSize() {
		return "", errors.New("bff: the sealed value is not readable")
	}
	plain, err := gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], []byte(binding))
	if err != nil {
		return "", errors.New("bff: the sealed value is not readable")
	}
	return string(plain), nil
}
