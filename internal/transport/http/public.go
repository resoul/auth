package http

import (
	"context"
	"net/http"

	"airlance.org/auth/internal/transport/http/openapi"
)

// jwksDocument is the key set as the JWT adapter encoded it, served byte for byte.
type jwksDocument []byte

// VisitGetJWKSResponse implements openapi.GetJWKSResponseObject.
func (d jwksDocument) VisitGetJWKSResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	// Short enough for a new key to reach verifiers within the rotation overlap.
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(d)
	return err
}

// GetJWKS serves the public keys that verify access tokens.
func (a *API) GetJWKS(context.Context, openapi.GetJWKSRequestObject) (openapi.GetJWKSResponseObject, error) {
	return a.jwks, nil
}

// GetHealthAlive answers while the process serves requests.
func (a *API) GetHealthAlive(context.Context, openapi.GetHealthAliveRequestObject) (openapi.GetHealthAliveResponseObject, error) {
	return openapi.GetHealthAlive200JSONResponse{Status: openapi.Ok}, nil
}

// GetHealthReady checks the dependencies of sign-in. The body never says which one failed.
func (a *API) GetHealthReady(ctx context.Context, _ openapi.GetHealthReadyRequestObject) (openapi.GetHealthReadyResponseObject, error) {
	checkCtx, cancel := context.WithTimeout(ctx, readyTimeout)
	defer cancel()
	if err := a.ready(checkCtx); err != nil {
		a.logger.WarnContext(ctx, "not ready", "error", err)
		return openapi.GetHealthReady503JSONResponse{Status: openapi.Unavailable}, nil
	}
	return openapi.GetHealthReady200JSONResponse{Status: openapi.Ok}, nil
}
