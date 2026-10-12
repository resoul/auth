package port

import (
	"context"

	"airlance.org/auth/internal/domain/deviceauth"
)

// DeviceRequestRepository stores the requests of devices that ask for a session.
type DeviceRequestRepository interface {
	// Create stores a new request.
	Create(ctx context.Context, r *deviceauth.Request) error
	// Get loads a request without locking it, for readers that change nothing: the status poll of the new device
	// and the view of the approving one. It returns ErrNotFound.
	Get(ctx context.Context, id deviceauth.RequestID) (*deviceauth.Request, error)
	// GetForUpdate loads a request and keeps it locked until the transaction ends, so two approvals, or two
	// redemptions, of one request are serialized. It returns ErrNotFound.
	GetForUpdate(ctx context.Context, id deviceauth.RequestID) (*deviceauth.Request, error)
	// Save writes the changed state of a request loaded by GetForUpdate.
	Save(ctx context.Context, r *deviceauth.Request) error
}

// DeviceSecrets issues the values of a request that must be unguessable. The poll secret is a ticket secret.
type DeviceSecrets interface {
	// NewRequestID creates the identifier a QR code carries.
	NewRequestID() (deviceauth.RequestID, error)
	// NewPairingCode creates the digits the new device shows and the approving device types.
	NewPairingCode() (string, error)
}
