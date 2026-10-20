package id_test

import (
	"testing"

	"go.airlance.org/auth/internal/adapter/id"
	"go.airlance.org/auth/internal/domain/identity"
)

func TestNewUserIDIsValidAndUnique(t *testing.T) {
	var gen id.Generator

	seen := make(map[identity.UserID]bool)

	for i := 0; i < 100; i++ {
		userID, err := gen.NewUserID()
		if err != nil {
			t.Fatalf("NewUserID: %v", err)
		}

		if _, err := identity.ParseUserID(userID.String()); err != nil {
			t.Fatalf("generated id %q is not a valid UserID: %v", userID, err)
		}

		if seen[userID] {
			t.Fatalf("duplicate id %q", userID)
		}

		seen[userID] = true
	}
}
