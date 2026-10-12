package identity_test

import (
	"errors"
	"testing"

	"airlance.org/auth/internal/domain/identity"
)

func TestParseUserID(t *testing.T) {
	const valid = "3f1b7c0e-5d2a-4b8e-9c61-0a1b2c3d4e5f"
	id, err := identity.ParseUserID(valid)
	if err != nil || id.String() != valid || id.IsZero() {
		t.Fatalf("ParseUserID(%q) = %q, %v", valid, id, err)
	}

	for _, in := range []string{
		"",
		"3f1b7c0e5d2a4b8e9c610a1b2c3d4e5f",      // no dashes
		"3F1B7C0E-5D2A-4B8E-9C61-0A1B2C3D4E5F",  // upper case is not canonical
		"3f1b7c0e-5d2a-1b8e-9c61-0a1b2c3d4e5f",  // version 1
		"3f1b7c0e-5d2a-4b8e-7c61-0a1b2c3d4e5f",  // bad variant
		"3f1b7c0e-5d2a-4b8e-9c61-0a1b2c3d4e5",   // short
		"3f1b7c0e-5d2a-4b8e-9c61-0a1b2c3d4e5fa", // long
		"3f1b7c0e-5d2a-4b8e-9c61-0a1b2c3d4e5g",  // not hex
		"018f3b2a-1c4d-7a5e-8b6f-9c0d1e2f3a4b",  // UUIDv7 is for other records
	} {
		if _, err := identity.ParseUserID(in); !errors.Is(err, identity.ErrInvalidID) {
			t.Errorf("ParseUserID(%q) error = %v, want ErrInvalidID", in, err)
		}
	}
}

func TestParseRecognizedClientID(t *testing.T) {
	const valid = "3f1b7c0e-5d2a-4b8e-9c61-0a1b2c3d4e5f"
	id, err := identity.ParseRecognizedClientID(valid)
	if err != nil || id.String() != valid {
		t.Fatalf("ParseRecognizedClientID(%q) = %q, %v", valid, id, err)
	}
	if _, err := identity.ParseRecognizedClientID("nope"); !errors.Is(err, identity.ErrInvalidID) {
		t.Errorf("error = %v, want ErrInvalidID", err)
	}
}
