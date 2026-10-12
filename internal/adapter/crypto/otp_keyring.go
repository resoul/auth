package crypto

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

const (
	otpKeyLength = 32
	// maxKeyFileSize bounds what is read from a key file; a valid file is 44 bytes plus whitespace.
	maxKeyFileSize = 1024
)

// OTPKeyring holds the HMAC keys of the OTP purpose by key ID and names the key
// used for new generations. Key material is never printed or returned.
type OTPKeyring struct {
	activeKID string
	keys      map[string][]byte
}

// NewOTPKeyring checks that every key is 32 bytes and that the active kid exists.
// It copies the key material.
func NewOTPKeyring(activeKID string, keys map[string][]byte) (*OTPKeyring, error) {
	if len(keys) == 0 {
		return nil, errors.New("otp keyring: no keys")
	}
	ring := &OTPKeyring{activeKID: activeKID, keys: make(map[string][]byte, len(keys))}
	for kid, key := range keys {
		if kid == "" {
			return nil, errors.New("otp keyring: empty kid")
		}
		if len(key) != otpKeyLength {
			return nil, fmt.Errorf("otp keyring: key %q must be %d bytes", kid, otpKeyLength)
		}
		ring.keys[kid] = append([]byte(nil), key...)
	}
	if _, ok := ring.keys[activeKID]; !ok {
		return nil, fmt.Errorf("otp keyring: active kid %q is not in keys", activeKID)
	}
	return ring, nil
}

// LoadOTPKeyring reads every key file (kid to path) and builds the keyring.
// A file holds standard base64 of 32 random bytes; surrounding whitespace is ignored.
// Errors name the kid and path, never the contents.
func LoadOTPKeyring(activeKID string, keyFiles map[string]string) (*OTPKeyring, error) {
	keys := make(map[string][]byte, len(keyFiles))
	for kid, path := range keyFiles {
		key, err := readOTPKeyFile(path)
		if err != nil {
			return nil, fmt.Errorf("otp key %q: %w", kid, err)
		}
		keys[kid] = key
	}
	return NewOTPKeyring(activeKID, keys)
}

func readOTPKeyFile(path string) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the path comes from the operator's keyring file, not request input
	if err != nil {
		return nil, fmt.Errorf("open key file: %w", err)
	}
	defer func() { _ = f.Close() }() // read-only file: a close error loses nothing

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat key file %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("key file %s is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxKeyFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read key file %s: %w", path, err)
	}
	if len(data) > maxKeyFileSize {
		return nil, fmt.Errorf("key file %s is too large", path)
	}
	key, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("key file %s is not valid base64", path)
	}
	if len(key) != otpKeyLength {
		return nil, fmt.Errorf("key file %s must hold %d bytes", path, otpKeyLength)
	}
	return key, nil
}

// ActiveKID returns the key ID used for new generations.
func (r *OTPKeyring) ActiveKID() string { return r.activeKID }

// KIDs returns all key IDs in sorted order.
func (r *OTPKeyring) KIDs() []string {
	kids := make([]string, 0, len(r.keys))
	for kid := range r.keys {
		kids = append(kids, kid)
	}
	sort.Strings(kids)
	return kids
}

// key looks the kid up in the ring. There is no fallback to the active key.
func (r *OTPKeyring) key(kid string) ([]byte, bool) {
	key, ok := r.keys[kid]
	return key, ok
}

// String and GoString keep key material out of %v and %#v output.
func (r *OTPKeyring) String() string {
	return fmt.Sprintf("otp keyring (active %q, %d keys)", r.activeKID, len(r.keys))
}

// GoString implements fmt.GoStringer.
func (r *OTPKeyring) GoString() string { return r.String() }
