package httpapi

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/ratelimit"
)

// refreshPerIP bounds how fast one address can spend refresh tokens. A phone
// refreshes once per access-token lifetime (15 minutes), so this is loose
// enough for an office of phones behind one NAT and still stops anyone
// hammering the endpoint with guessed tokens.
var refreshPerIP = ratelimit.Rule{Name: "refresh:ip", Limit: 300, Window: 15 * time.Minute}

// withClient copies the optional client/device fields of a sign-in body onto
// the request context. An unknown client is a 400 rather than a silent web
// session: a mobile build sending a typo would otherwise never get a refresh
// token and nobody would notice until users got signed out.
func withClient(rc account.RequestContext, client *SessionClient, device, version *string) (account.RequestContext, bool) {
	if client != nil {
		if !client.Valid() {
			return rc, false
		}
		rc.Client = account.Client(*client)
	}
	rc.DeviceName = deref(device)
	rc.AppVersion = deref(version)
	return rc, true
}

// clientForPasswordChange keeps a phone a phone: the fresh session handed back
// by a password change inherits the current session's client unless the body
// names one.
func (s *Server) clientForPasswordChange(ctx context.Context, client *SessionClient, device, version *string) (account.RequestContext, bool) {
	rc := requestContextFrom(ctx)
	if client == nil {
		if id, ok := account.SessionID(ctx); ok {
			if cur, err := s.accounts.SessionClientInfo(ctx, id); err == nil {
				rc.Client, rc.DeviceName, rc.AppVersion = cur.Client, cur.DeviceName, cur.AppVersion
			}
		}
		if device != nil {
			rc.DeviceName = *device
		}
		if version != nil {
			rc.AppVersion = *version
		}
		return rc, true
	}
	return withClient(rc, client, device, version)
}

func (s *Server) RefreshSession(ctx context.Context, request RefreshSessionRequestObject) (RefreshSessionResponseObject, error) {
	if request.Body == nil {
		return RefreshSession400JSONResponse{BadRequestJSONResponse(errorBody("invalid_json", "a JSON body is required"))}, nil
	}
	rc := requestContextFrom(ctx)
	if res := s.allow(ctx, rc.IP, refreshPerIP); !res.Allowed {
		return RefreshSession429JSONResponse{tooMany(res, "too many token refreshes from this address; try again later")}, nil
	}
	rc.AppVersion = deref(request.Body.AppVersion)

	creds, err := s.accounts.Refresh(ctx, request.Body.RefreshToken, rc)
	switch {
	case errors.Is(err, account.ErrRefreshReused):
		return RefreshSession401JSONResponse(errorBody("refresh_token_reused", err.Error())), nil
	case errors.Is(err, account.ErrRefreshInvalid):
		return RefreshSession401JSONResponse(errorBody("invalid_refresh_token", err.Error())), nil
	case err != nil:
		log.Printf("refresh: %v", err)
		return nil, err
	}
	return RefreshSession200JSONResponse(credentialsToAPI(creds)), nil
}

func (s *Server) ListSessions(ctx context.Context, _ ListSessionsRequestObject) (ListSessionsResponseObject, error) {
	user, ok := account.CurrentUser(ctx)
	if !ok {
		return ListSessions401JSONResponse{UnauthorizedJSONResponse(errorBody("unauthenticated", "no session"))}, nil
	}
	current, _ := account.SessionID(ctx)
	sessions, err := s.accounts.ListSessions(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	out := make([]DeviceSession, 0, len(sessions))
	for _, d := range sessions {
		out = append(out, DeviceSession{
			Id:         mustUUID(d.ID),
			Client:     SessionClient(d.Client),
			DeviceName: d.DeviceName,
			AppVersion: d.AppVersion,
			UserAgent:  d.UserAgent,
			Ip:         d.IP,
			Current:    d.ID == current,
			CreatedAt:  d.CreatedAt,
			LastSeenAt: d.LastSeenAt,
			ExpiresAt:  d.ExpiresAt,
		})
	}
	return ListSessions200JSONResponse{Sessions: out}, nil
}

func (s *Server) RevokeSession(ctx context.Context, request RevokeSessionRequestObject) (RevokeSessionResponseObject, error) {
	user, ok := account.CurrentUser(ctx)
	if !ok {
		return RevokeSession401JSONResponse{UnauthorizedJSONResponse(errorBody("unauthenticated", "no session"))}, nil
	}
	err := s.accounts.RevokeSessionByID(ctx, user.ID, request.SessionId.String())
	switch {
	case errors.Is(err, account.ErrNotFound):
		return RevokeSession404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "session not found"))}, nil
	case err != nil:
		return nil, err
	}
	return RevokeSession204Response{}, nil
}
