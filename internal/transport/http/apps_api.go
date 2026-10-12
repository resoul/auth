package http

import (
	"context"

	"airlance.org/auth/internal/application/port"
	"airlance.org/auth/internal/transport/http/openapi"
)

// apiConnectedApp is a live grant as the person sees it. Nothing of a token, a secret or a hash is in it.
func apiConnectedApp(g port.AppGrant) openapi.ConnectedApp {
	resources := make([]openapi.ConnectedAppResource, 0, len(g.Resources))
	for _, r := range g.Resources {
		resources = append(resources, openapi.ConnectedAppResource{Id: r.ID, Name: r.Name, Scopes: append([]string{}, r.Scopes...)})
	}
	return openapi.ConnectedApp{
		GrantId: g.ID, ClientId: g.ClientID, Name: g.ClientName, Scopes: append([]string{}, g.Scopes...), Resources: resources,
		CreatedAt: g.CreatedAt.UTC(), LastActiveAt: g.LastUsedAt.UTC(), ExpiresAt: g.ExpiresAt.UTC(),
	}
}

// listApps reads the caller's own grants; ok is false when the caller is not authenticated.
func (a *API) listApps(ctx context.Context) (body openapi.ConnectedAppList, ok bool, err error) {
	actor, ok, err := a.authenticate(ctx)
	if err != nil || !ok {
		return openapi.ConnectedAppList{}, false, err
	}
	grants, err := a.apps.List(ctx, actor.UserID)
	if err != nil {
		return openapi.ConnectedAppList{}, false, err
	}
	body.Apps = make([]openapi.ConnectedApp, 0, len(grants))
	for _, g := range grants {
		body.Apps = append(body.Apps, apiConnectedApp(g))
	}
	return body, true, nil
}

// revokeAppGrant ends one grant of the caller. A grant that is another's, over, or not there gives the same result.
func (a *API) revokeAppGrant(ctx context.Context, id string) (authenticated bool, err error) {
	actor, ok, err := a.authenticate(ctx)
	if err != nil || !ok {
		return false, err
	}
	return true, a.apps.RevokeGrant(ctx, actor.UserID, id)
}

// revokeApp ends every grant of the caller's with one application.
func (a *API) revokeApp(ctx context.Context, clientID string) (authenticated bool, err error) {
	actor, ok, err := a.authenticate(ctx)
	if err != nil || !ok {
		return false, err
	}
	return true, a.apps.RevokeClient(ctx, actor.UserID, clientID)
}

// Browser operations.

func (a *API) BrowserListApps(ctx context.Context, _ openapi.BrowserListAppsRequestObject) (openapi.BrowserListAppsResponseObject, error) {
	body, ok, err := a.listApps(ctx)
	if err != nil {
		return nil, err
	}
	if !ok {
		return openapi.BrowserListApps401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}
	return openapi.BrowserListApps200JSONResponse(body), nil
}

func (a *API) BrowserRevokeAppGrant(ctx context.Context, req openapi.BrowserRevokeAppGrantRequestObject) (openapi.BrowserRevokeAppGrantResponseObject, error) {
	ok, err := a.revokeAppGrant(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	if !ok {
		return openapi.BrowserRevokeAppGrant401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}
	return openapi.BrowserRevokeAppGrant204Response{}, nil
}

func (a *API) BrowserRevokeApp(ctx context.Context, req openapi.BrowserRevokeAppRequestObject) (openapi.BrowserRevokeAppResponseObject, error) {
	ok, err := a.revokeApp(ctx, req.ClientId)
	if err != nil {
		return nil, err
	}
	if !ok {
		return openapi.BrowserRevokeApp401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}
	return openapi.BrowserRevokeApp204Response{}, nil
}

// Native operations: the same use cases, no cookies.

func (a *API) NativeListApps(ctx context.Context, _ openapi.NativeListAppsRequestObject) (openapi.NativeListAppsResponseObject, error) {
	body, ok, err := a.listApps(ctx)
	if err != nil {
		return nil, err
	}
	if !ok {
		return openapi.NativeListApps401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}
	return openapi.NativeListApps200JSONResponse(body), nil
}

func (a *API) NativeRevokeAppGrant(ctx context.Context, req openapi.NativeRevokeAppGrantRequestObject) (openapi.NativeRevokeAppGrantResponseObject, error) {
	ok, err := a.revokeAppGrant(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	if !ok {
		return openapi.NativeRevokeAppGrant401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}
	return openapi.NativeRevokeAppGrant204Response{}, nil
}

func (a *API) NativeRevokeApp(ctx context.Context, req openapi.NativeRevokeAppRequestObject) (openapi.NativeRevokeAppResponseObject, error) {
	ok, err := a.revokeApp(ctx, req.ClientId)
	if err != nil {
		return nil, err
	}
	if !ok {
		return openapi.NativeRevokeApp401JSONResponse{UnauthenticatedJSONResponse: unauthenticated(ctx)}, nil
	}
	return openapi.NativeRevokeApp204Response{}, nil
}
