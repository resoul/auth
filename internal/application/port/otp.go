package port

import "airlance.org/auth/internal/domain/authflow"

// OTPGeneration is the fresh per-generation material of a flow: a random salt and
// the ID of the key that will derive the code. Both are stored with the flow.
type OTPGeneration struct {
	Salt  []byte
	KeyID string
}

// OTPGenerations creates the material for a new code generation (start and resend).
type OTPGenerations interface {
	NewGeneration() (OTPGeneration, error)
}

// OTPCodes derives and checks codes from the stored state of a flow, using the
// key recorded in the flow rather than the currently active one.
type OTPCodes interface {
	// Code returns the code of the flow's current generation, for the mail worker.
	Code(f *authflow.Flow) (string, error)
	// Matches reports whether submitted equals the flow's code. Input that is not
	// exactly eight ASCII digits does not match. An error means the code could not
	// be derived (unknown key, closed flow) and is not an expected denial.
	Matches(f *authflow.Flow, submitted string) (bool, error)
}
