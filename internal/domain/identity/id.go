package identity

import (
	"errors"
	"strings"
)

// ErrInvalidID reports a malformed identifier.
var ErrInvalidID = errors.New("invalid id")

// UserID identifies a User. It is a canonical lower-case UUIDv4.
type UserID struct {
	value string
}

// RecognizedClientID identifies a RecognizedClient. It is a canonical lower-case UUIDv4.
type RecognizedClientID struct {
	value string
}

// ParseUserID validates the canonical UUIDv4 text form.
func ParseUserID(s string) (UserID, error) {
	if !isUUIDv4(s) {
		return UserID{}, ErrInvalidID
	}

	return UserID{value: s}, nil
}

// ParseRecognizedClientID validates the canonical UUIDv4 text form.
func ParseRecognizedClientID(s string) (RecognizedClientID, error) {
	if !isUUIDv4(s) {
		return RecognizedClientID{}, ErrInvalidID
	}

	return RecognizedClientID{value: s}, nil
}

// String returns the canonical text form.
func (id UserID) String() string { return id.value }

// IsZero reports whether id is the invalid zero value.
func (id UserID) IsZero() bool { return id.value == "" }

// String returns the canonical text form.
func (id RecognizedClientID) String() string { return id.value }

// IsZero reports whether id is the invalid zero value.
func (id RecognizedClientID) IsZero() bool { return id.value == "" }

// isUUIDv4 accepts 8-4-4-4-12 lower-case hex with version 4 and RFC 4122 variant.
func isUUIDv4(s string) bool {
	if len(s) != 36 {
		return false
	}

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !isLowerHex(c) {
				return false
			}
		}
	}

	return s[14] == '4' && strings.IndexByte("89ab", s[19]) >= 0
}

func isLowerHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f'
}
