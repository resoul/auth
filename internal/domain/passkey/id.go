package passkey

import "errors"

// ErrInvalidID reports a malformed identifier.
var ErrInvalidID = errors.New("invalid passkey record id")

// ID identifies a credential, challenge, ticket or recovery code row. It is a
// canonical lower-case UUIDv7; the repositories keep the kinds apart.
type ID struct {
	value string
}

// ParseID validates the canonical UUIDv7 text form.
func ParseID(s string) (ID, error) {
	if !isUUIDv7(s) {
		return ID{}, ErrInvalidID
	}

	return ID{value: s}, nil
}

// String returns the canonical text form.
func (id ID) String() string { return id.value }

// IsZero reports whether id is the invalid zero value.
func (id ID) IsZero() bool { return id.value == "" }

// isUUIDv7 accepts 8-4-4-4-12 lower-case hex with version 7 and RFC 4122 variant.
func isUUIDv7(s string) bool {
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
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}

	return s[14] == '7' && (s[19] == '8' || s[19] == '9' || s[19] == 'a' || s[19] == 'b')
}
