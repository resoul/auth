package domain

import "errors"

// Sentinel errors returned by services.
// The transport layer maps these to HTTP status codes via utils.MapError —
// never hard-code status codes for these conditions in handlers.

var (
	// ErrNotFound is returned when a requested resource does not exist.
	ErrNotFound = errors.New("not found")

	// ErrConflict is returned when a resource already exists or a unique constraint is violated.
	ErrConflict = errors.New("conflict")

	// ErrUnauthorized is returned when the caller is not authenticated.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrForbidden is returned when the caller is authenticated but lacks permission.
	ErrForbidden = errors.New("forbidden")

	// ErrInvalidInput is returned when request input fails validation.
	ErrInvalidInput = errors.New("invalid input")
)
