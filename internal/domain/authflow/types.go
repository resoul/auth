package authflow

import (
	"encoding/base64"
	"errors"
	"time"
)

const (
	flowIDBytes = 16
	// SaltLength is the OTP salt size in bytes.
	SaltLength = 16
)

// FlowID is the unguessable flow identifier: 16 random bytes in unpadded base64url.
type FlowID struct {
	value string
}

// ParseFlowID validates the textual form produced by the flow ID generator.
func ParseFlowID(s string) (FlowID, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	// The decoder skips CR and LF, so the canonical re-encoding must match the input.
	if err != nil || len(raw) != flowIDBytes || base64.RawURLEncoding.EncodeToString(raw) != s {
		return FlowID{}, errors.New("invalid flow id")
	}

	return FlowID{value: s}, nil
}

// NewFlowID encodes 16 random bytes. The caller provides cryptographic randomness.
func NewFlowID(random [flowIDBytes]byte) FlowID {
	return FlowID{value: base64.RawURLEncoding.EncodeToString(random[:])}
}

// String returns the textual form used in storage, requests and OTP derivation.
func (id FlowID) String() string { return id.value }

// IsZero reports whether id is the invalid zero value.
func (id FlowID) IsZero() bool { return id.value == "" }

// Purpose tells what a flow proves. Purposes are not interchangeable.
type Purpose string

// Flow purposes.
const (
	PurposeLogin       Purpose = "login"
	PurposeStepUp      Purpose = "step_up"
	PurposeChangeEmail Purpose = "change_email"
)

func (p Purpose) valid() bool {
	switch p {
	case PurposeLogin, PurposeStepUp, PurposeChangeEmail:
		return true
	}

	return false
}

// State is the lifecycle state of a flow. A flow starts pending and never leaves a final state.
type State string

// Flow states.
const (
	StatePending  State = "pending"
	StateConsumed State = "consumed"
	StateLocked   State = "locked"
	StateExpired  State = "expired"
)

func (s State) valid() bool {
	switch s {
	case StatePending, StateConsumed, StateLocked, StateExpired:
		return true
	}

	return false
}

// QuotaClass is chosen by the server at start and kept for the whole flow.
type QuotaClass string

// Quota classes.
const (
	QuotaUnknown    QuotaClass = "unknown"
	QuotaRecognized QuotaClass = "recognized"
)

func (c QuotaClass) valid() bool { return c == QuotaUnknown || c == QuotaRecognized }

// Policy holds the flow limits. DefaultPolicy has the initial values.
type Policy struct {
	TTL         time.Duration
	MaxAttempts int
	ResendPause time.Duration
}

// DefaultPolicy returns the initial limits profile.
func DefaultPolicy() Policy {
	return Policy{TTL: 10 * time.Minute, MaxAttempts: 5, ResendPause: 60 * time.Second}
}

// Validate rejects limits that make a flow unusable.
func (p Policy) Validate() error {
	if p.TTL <= 0 || p.MaxAttempts <= 0 || p.ResendPause < 0 {
		return errors.New("invalid flow policy")
	}

	return nil
}
