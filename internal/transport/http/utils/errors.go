package utils

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/resoul/api/internal/domain"
	"gorm.io/gorm"
)

// HTTPError is the structured error returned to the client.
type HTTPError struct {
	Status  int
	Code    string
	Message string
}

// MapError converts a domain sentinel error into an HTTPError.
// Add new mappings here as new domain errors are introduced —
// never duplicate this table in handler code.
//
// Mapping table:
//
//	domain.ErrNotFound          → 404 not_found
//	gorm.ErrRecordNotFound      → 404 not_found
//	domain.ErrConflict          → 409 conflict
//	domain.ErrUnauthorized      → 401 unauthorized
//	domain.ErrForbidden         → 403 forbidden
//	domain.ErrInvalidInput      → 400 invalid_input
//	anything else               → 500 internal_error
func MapError(err error) HTTPError {
	switch {
	case errors.Is(err, domain.ErrNotFound),
		errors.Is(err, gorm.ErrRecordNotFound):
		return HTTPError{
			Status:  http.StatusNotFound,
			Code:    "not_found",
			Message: err.Error(),
		}

	case errors.Is(err, domain.ErrConflict):
		return HTTPError{
			Status:  http.StatusConflict,
			Code:    "conflict",
			Message: err.Error(),
		}

	case errors.Is(err, domain.ErrUnauthorized):
		return HTTPError{
			Status:  http.StatusUnauthorized,
			Code:    "unauthorized",
			Message: err.Error(),
		}

	case errors.Is(err, domain.ErrForbidden):
		return HTTPError{
			Status:  http.StatusForbidden,
			Code:    "forbidden",
			Message: err.Error(),
		}

	case errors.Is(err, domain.ErrInvalidInput):
		return HTTPError{
			Status:  http.StatusBadRequest,
			Code:    "invalid_input",
			Message: err.Error(),
		}

	default:
		return HTTPError{
			Status:  http.StatusInternalServerError,
			Code:    "internal_error",
			Message: "an unexpected error occurred",
		}
	}
}

// RespondMapped maps err to an HTTP status code and writes a JSON error response.
// Use this in every handler instead of hand-coding status codes for domain errors.
func RespondMapped(c *gin.Context, err error) {
	mapped := MapError(err)
	RespondError(c, mapped.Status, mapped.Code, mapped.Message)
}
