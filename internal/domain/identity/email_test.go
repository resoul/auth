package identity_test

import (
	"errors"
	"strings"
	"testing"

	"airlance.org/auth/internal/domain/identity"
)

func TestParseEmailNormalizes(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"plain", "alice@example.com", "alice@example.com"},
		{"outer spaces", "  alice@example.com\t\n", "alice@example.com"},
		{"case", "Alice.Smith@Example.COM", "alice.smith@example.com"},
		{"plus tag kept", "alice+tag@example.com", "alice+tag@example.com"},
		{"gmail dots kept", "a.l.i.c.e@gmail.com", "a.l.i.c.e@gmail.com"},
		{"subdomain", "a@mail.example.co.uk", "a@mail.example.co.uk"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := identity.ParseEmail(tt.in)
			if err != nil {
				t.Fatalf("ParseEmail(%q): %v", tt.in, err)
			}
			if got.String() != tt.want {
				t.Errorf("ParseEmail(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseEmailSameAddressDifferentSpelling(t *testing.T) {
	a, _ := identity.ParseEmail("Alice@Example.com ")
	b, _ := identity.ParseEmail("alice@example.COM")
	if a != b {
		t.Errorf("%q and %q should be equal", a, b)
	}
}

func TestParseEmailRejects(t *testing.T) {
	tests := []struct{ name, in string }{
		{"empty", ""},
		{"spaces only", "   "},
		{"no at", "alice.example.com"},
		{"no domain", "alice@"},
		{"no local", "@example.com"},
		{"no dot in domain", "alice@localhost"},
		{"two ats", "a@b@example.com"},
		{"display name", "Alice <alice@example.com>"},
		{"angle brackets", "<alice@example.com>"},
		{"comment", "alice@example.com (home)"},
		{"inner space", "ali ce@example.com"},
		{"quoted local with space", `"ali ce"@example.com`},
		{"list", "a@example.com, b@example.com"},
		{"non ascii local", "алиса@example.com"},
		{"non ascii domain", "alice@пример.рф"},
		{"control char", "alice\x00@example.com"},
		{"newline inside", "alice@example.com\nbcc: x@example.com"},
		{"local too long", strings.Repeat("a", 65) + "@example.com"},
		{"too long", strings.Repeat("a", 60) + "@" + strings.Repeat("b.", 100) + "com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := identity.ParseEmail(tt.in)
			if !errors.Is(err, identity.ErrInvalidEmail) {
				t.Fatalf("ParseEmail(%q) = %q, %v; want ErrInvalidEmail", tt.in, got, err)
			}
			if !got.IsZero() {
				t.Errorf("ParseEmail(%q) returned non-zero value %q", tt.in, got)
			}
		})
	}
}

func TestEmailZeroValue(t *testing.T) {
	var e identity.Email
	if !e.IsZero() || e.String() != "" {
		t.Errorf("zero Email = %q, IsZero=%v", e, e.IsZero())
	}
}
