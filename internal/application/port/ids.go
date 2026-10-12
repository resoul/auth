package port

import (
	"airlance.org/auth/internal/domain/authflow"
	"airlance.org/auth/internal/domain/identity"
	"airlance.org/auth/internal/domain/session"
	"airlance.org/auth/internal/domain/token"
)

// UserIDGenerator creates User identifiers.
type UserIDGenerator interface {
	NewUserID() (identity.UserID, error)
}

// FlowIDGenerator creates unguessable flow identifiers from cryptographic randomness.
type FlowIDGenerator interface {
	NewFlowID() (authflow.FlowID, error)
}

// RecognizedClientIDGenerator creates RecognizedClient identifiers.
type RecognizedClientIDGenerator interface {
	NewRecognizedClientID() (identity.RecognizedClientID, error)
}

// SessionIDGenerator creates session identifiers (UUIDv7).
type SessionIDGenerator interface {
	NewSessionID() (session.ID, error)
}

// RefreshTokenIDGenerator creates refresh token row and family identifiers (UUIDv7).
type RefreshTokenIDGenerator interface {
	NewRefreshTokenID() (token.ID, error)
	NewFamilyID() (token.FamilyID, error)
}
