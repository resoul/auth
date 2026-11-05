package http

import (
	"context"
	"net/http"

	"go.airlance.org/auth/internal/transport/http/openapi"
)

type jwksDocument []byte

func (d jwksDocument) VisitGetJWKSResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(d)

	return err
}

func (a *API) GetJWKS(context.Context, openapi.GetJWKSRequestObject) (openapi.GetJWKSResponseObject, error) {
	return a.jwks, nil
}

func (a *API) GetHealthAlive(context.Context, openapi.GetHealthAliveRequestObject) (openapi.GetHealthAliveResponseObject, error) {
	return openapi.GetHealthAlive200JSONResponse{Status: openapi.Ok}, nil
}

func (a *API) GetHealthReady(ctx context.Context, _ openapi.GetHealthReadyRequestObject) (openapi.GetHealthReadyResponseObject, error) {
	checkCtx, cancel := context.WithTimeout(ctx, readyTimeout)
	defer cancel()

	if err := a.ready(checkCtx); err != nil {
		a.logger.WarnContext(ctx, "not ready", "error", err)
		return openapi.GetHealthReady503JSONResponse{Status: openapi.Unavailable}, nil
	}

	return openapi.GetHealthReady200JSONResponse{Status: openapi.Ok}, nil
}
