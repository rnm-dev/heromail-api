package httpapi

import (
	"context"
	"errors"
	"log"

	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/push"
)

func (s *Server) RegisterPushDevice(ctx context.Context, request RegisterPushDeviceRequestObject) (RegisterPushDeviceResponseObject, error) {
	user, ok := account.CurrentUser(ctx)
	sessionID, hasSession := account.SessionID(ctx)
	if !ok || !hasSession {
		return RegisterPushDevice401JSONResponse{UnauthorizedJSONResponse(errorBody("unauthenticated", "no session"))}, nil
	}
	if request.Body == nil {
		return RegisterPushDevice400JSONResponse{BadRequestJSONResponse(errorBody("invalid_json", "a JSON body is required"))}, nil
	}
	reg := push.Registration{
		Token:      request.Body.Token,
		Platform:   string(request.Body.Platform),
		Locale:     deref(request.Body.Locale),
		Timezone:   deref(request.Body.Timezone),
		AppVersion: deref(request.Body.AppVersion),
	}
	if request.Body.Provider != nil {
		reg.Provider = string(*request.Body.Provider)
	}
	d, err := push.NewStore(s.pool).Register(ctx, user.ID, sessionID, reg)
	switch {
	case errors.Is(err, push.ErrValidation):
		return RegisterPushDevice400JSONResponse{BadRequestJSONResponse(errorBody("validation_failed", err.Error()))}, nil
	case err != nil:
		log.Printf("register push device: %v", err)
		return nil, err
	}
	return RegisterPushDevice200JSONResponse{
		Id:         mustUUID(d.ID),
		SessionId:  mustUUID(d.SessionID),
		Platform:   PushDevicePlatform(d.Platform),
		Provider:   PushDeviceProvider(d.Provider),
		Locale:     d.Locale,
		Timezone:   d.Timezone,
		AppVersion: d.AppVersion,
		Disabled:   d.DisabledAt != nil,
		CreatedAt:  d.CreatedAt,
		LastSeenAt: d.LastSeenAt,
	}, nil
}

func (s *Server) UnregisterPushDevice(ctx context.Context, _ UnregisterPushDeviceRequestObject) (UnregisterPushDeviceResponseObject, error) {
	sessionID, ok := account.SessionID(ctx)
	if !ok {
		return UnregisterPushDevice401JSONResponse{UnauthorizedJSONResponse(errorBody("unauthenticated", "no session"))}, nil
	}
	if err := push.NewStore(s.pool).Unregister(ctx, sessionID); err != nil {
		return nil, err
	}
	return UnregisterPushDevice204Response{}, nil
}
