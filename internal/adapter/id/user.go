package id

import (
	"fmt"

	"github.com/google/uuid"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/operator"
	"go.airlance.org/auth/internal/domain/passkey"
	"go.airlance.org/auth/internal/domain/session"
	"go.airlance.org/auth/internal/domain/token"
)

var _ port.UserIDGenerator = Generator{}

type Generator struct{}

func (Generator) NewUserID() (identity.UserID, error) {
	u, err := uuid.NewRandom()
	if err != nil {
		return identity.UserID{}, fmt.Errorf("generate user id: %w", err)
	}

	return identity.ParseUserID(u.String())
}

func (Generator) NewRecordID() (uuid.UUID, error) {
	u, err := uuid.NewV7()
	if err != nil {
		return uuid.UUID{}, fmt.Errorf("generate record id: %w", err)
	}

	return u, nil
}

var (
	_ port.RecognizedClientIDGenerator = Generator{}
	_ port.SessionIDGenerator          = Generator{}
	_ port.RefreshTokenIDGenerator     = Generator{}
)

func (Generator) NewSessionID() (session.ID, error) {
	u, err := uuid.NewV7()
	if err != nil {
		return session.ID{}, fmt.Errorf("generate session id: %w", err)
	}

	return session.ParseID(u.String())
}

func (Generator) NewRefreshTokenID() (token.ID, error) {
	u, err := uuid.NewV7()
	if err != nil {
		return token.ID{}, fmt.Errorf("generate refresh token id: %w", err)
	}

	return token.ParseID(u.String())
}

func (Generator) NewFamilyID() (token.FamilyID, error) {
	u, err := uuid.NewV7()
	if err != nil {
		return token.FamilyID{}, fmt.Errorf("generate family id: %w", err)
	}

	return token.ParseFamilyID(u.String())
}

func (Generator) NewRecognizedClientID() (identity.RecognizedClientID, error) {
	u, err := uuid.NewRandom()
	if err != nil {
		return identity.RecognizedClientID{}, fmt.Errorf("generate recognized client id: %w", err)
	}

	return identity.ParseRecognizedClientID(u.String())
}

var _ port.PasskeyIDGenerator = Generator{}

func (Generator) NewPasskeyID() (passkey.ID, error) {
	u, err := uuid.NewV7()
	if err != nil {
		return passkey.ID{}, fmt.Errorf("generate passkey record id: %w", err)
	}

	return passkey.ParseID(u.String())
}

var _ port.OperatorIDGenerator = Generator{}

func (Generator) NewOperatorID() (operator.ID, error) {
	u, err := uuid.NewRandom()
	if err != nil {
		return operator.ID{}, fmt.Errorf("generate operator id: %w", err)
	}

	return operator.ParseID(u.String())
}

var _ port.OIDCIDGenerator = Generator{}

func (Generator) NewOIDCID() (string, error) {
	u, err := uuid.NewV7()
	if err != nil {
		return "", fmt.Errorf("generate oidc id: %w", err)
	}

	return u.String(), nil
}
