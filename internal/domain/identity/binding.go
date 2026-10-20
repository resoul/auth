package identity

import (
	"crypto/subtle"
	"errors"
)

// BindingHashLength is the size of the stored client binding hash (SHA-256).
const BindingHashLength = 32

// BindingHash is the stored SHA-256 hash of the client binding secret. A flow,
// a session and a recognized client keep the hash, never the secret.
type BindingHash struct {
	value [BindingHashLength]byte
	set   bool
}

// NewBindingHash wraps a hash of exactly BindingHashLength bytes.
func NewBindingHash(hash []byte) (BindingHash, error) {
	if len(hash) != BindingHashLength {
		return BindingHash{}, errors.New("binding hash must be 32 bytes")
	}

	var h BindingHash
	copy(h.value[:], hash)
	h.set = true

	return h, nil
}

// Bytes returns a copy of the hash.
func (h BindingHash) Bytes() []byte { return append([]byte(nil), h.value[:]...) }

// IsZero reports whether h is the invalid zero value.
func (h BindingHash) IsZero() bool { return !h.set }

// Equal compares two hashes in constant time; a zero value equals nothing.
func (h BindingHash) Equal(other BindingHash) bool {
	return h.set && other.set && subtle.ConstantTimeCompare(h.value[:], other.value[:]) == 1
}
