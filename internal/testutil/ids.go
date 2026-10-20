package testutil

import (
	"encoding/binary"
	"fmt"
	"sync/atomic"

	"go.airlance.org/auth/internal/application/port"
	"go.airlance.org/auth/internal/domain/authflow"
	"go.airlance.org/auth/internal/domain/identity"
	"go.airlance.org/auth/internal/domain/operator"
	"go.airlance.org/auth/internal/domain/passkey"
	"go.airlance.org/auth/internal/domain/session"
	"go.airlance.org/auth/internal/domain/token"
)

var (
	_ port.UserIDGenerator         = (*SequentialIDs)(nil)
	_ port.FlowIDGenerator         = (*SequentialIDs)(nil)
	_ port.SessionIDGenerator      = (*SequentialIDs)(nil)
	_ port.RefreshTokenIDGenerator = (*SequentialIDs)(nil)
	_ port.PasskeyIDGenerator      = (*SequentialIDs)(nil)
	_ port.OperatorIDGenerator     = (*SequentialIDs)(nil)
	_ port.OIDCIDGenerator         = (*SequentialIDs)(nil)
)

type SequentialIDs struct {
	n atomic.Uint64
}

func (s *SequentialIDs) NewUserID() (identity.UserID, error) {
	return identity.ParseUserID(s.uuid())
}

func (s *SequentialIDs) NewRecognizedClientID() (identity.RecognizedClientID, error) {
	return identity.ParseRecognizedClientID(s.uuid())
}

func (s *SequentialIDs) NewFlowID() (authflow.FlowID, error) {
	var raw [16]byte
	binary.BigEndian.PutUint64(raw[8:], s.n.Add(1))

	return authflow.NewFlowID(raw), nil
}

func (s *SequentialIDs) NewOperatorID() (operator.ID, error) {
	return operator.ParseID(s.uuid())
}

func (s *SequentialIDs) uuid() string {
	return fmt.Sprintf("00000000-0000-4000-8000-%012x", s.n.Add(1))
}

func (s *SequentialIDs) NewSessionID() (session.ID, error) {
	return session.ParseID(s.uuid7())
}

func (s *SequentialIDs) NewRefreshTokenID() (token.ID, error) {
	return token.ParseID(s.uuid7())
}

func (s *SequentialIDs) NewFamilyID() (token.FamilyID, error) {
	return token.ParseFamilyID(s.uuid7())
}

func (s *SequentialIDs) uuid7() string {
	return fmt.Sprintf("00000000-0000-7000-8000-%012x", s.n.Add(1))
}

func (s *SequentialIDs) NewPasskeyID() (passkey.ID, error) {
	return passkey.ParseID(s.uuid7())
}

func (s *SequentialIDs) NewOIDCID() (string, error) {
	return s.uuid7(), nil
}
