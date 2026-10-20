package identity

import (
	"errors"
	"net/mail"
	"strings"
)

const (
	maxEmailLength     = 254
	maxEmailLocalPart  = 64
	asciiPrintableLow  = 0x21
	asciiPrintableHigh = 0x7e
)

// ErrInvalidEmail reports that the input is not a deliverable plain address.
var ErrInvalidEmail = errors.New("invalid email")

// Email is a normalized email address: outer spaces removed and lower-cased.
// The zero value is invalid. Gmail alias rules are not applied.
type Email struct {
	value string
}

// ParseEmail normalizes and validates a bare ASCII address such as user@example.com.
// Display names, comments, groups and non-ASCII characters are rejected.
func ParseEmail(raw string) (Email, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" || len(value) > maxEmailLength {
		return Email{}, ErrInvalidEmail
	}

	for i := 0; i < len(value); i++ {
		if c := value[i]; c < asciiPrintableLow || c > asciiPrintableHigh {
			return Email{}, ErrInvalidEmail
		}
	}

	addr, err := mail.ParseAddress(value)
	if err != nil || addr.Name != "" || addr.Address != value {
		return Email{}, ErrInvalidEmail
	}

	local, domain, ok := strings.Cut(value, "@")
	if !ok || local == "" || len(local) > maxEmailLocalPart || !strings.Contains(domain, ".") {
		return Email{}, ErrInvalidEmail
	}

	return Email{value: value}, nil
}

// String returns the normalized address.
func (e Email) String() string { return e.value }

// IsZero reports whether e is the invalid zero value.
func (e Email) IsZero() bool { return e.value == "" }
