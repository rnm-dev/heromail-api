package httpapi

import (
	"context"
	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/workspace"
)

func (s *Server) UpdateMessageFlags(ctx context.Context, r UpdateMessageFlagsRequestObject) (UpdateMessageFlagsResponseObject, error) {
	fail := func(code int, msg string) (UpdateMessageFlagsResponseObject, error) {
		return UpdateMessageFlagsdefaultJSONResponse{StatusCode: code, Body: errorBody("flags_failed", msg)}, nil
	}
	if r.Body == nil || (r.Body.Read == nil && r.Body.Starred == nil) {
		return fail(400, "read or starred is required")
	}
	ws, _, err := s.scope(ctx, string(r.Slug), workspace.RoleMember)
	if err != nil {
		return fail(404, "message not found")
	}
	msg, err := s.readableMessage(ctx, ws, r.MessageId.String())
	if err != nil {
		return fail(404, "message not found")
	}
	updated, err := s.inbound.UpdateFlags(ctx, msg.MailboxID, msg.ID, r.Body.Read, r.Body.Starred)
	if err != nil {
		return nil, err
	}
	return UpdateMessageFlags200JSONResponse(receivedMessageToAPI(updated)), nil
}

func (s *Server) GetUnreadCounts(ctx context.Context, _ GetUnreadCountsRequestObject) (GetUnreadCountsResponseObject, error) {
	user, ok := account.CurrentUser(ctx)
	if !ok {
		return GetUnreadCounts401JSONResponse{UnauthorizedJSONResponse(errorBody("unauthenticated", "no session"))}, nil
	}
	counts, err := s.inbound.UnreadCounts(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	return GetUnreadCounts200JSONResponse(counts), nil
}
