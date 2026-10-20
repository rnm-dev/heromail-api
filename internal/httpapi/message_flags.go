package httpapi

import (
	"context"
	"errors"

	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/inbound"
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

func (s *Server) GetUnreadCounts(ctx context.Context, r GetUnreadCountsRequestObject) (GetUnreadCountsResponseObject, error) {
	user, ok := account.CurrentUser(ctx)
	if !ok {
		return GetUnreadCounts401JSONResponse{UnauthorizedJSONResponse(errorBody("unauthenticated", "no session"))}, nil
	}
	// An unreadable box simply counts nothing: the access predicate still applies.
	var box *string
	if r.Params.Box != nil {
		id := r.Params.Box.String()
		box = &id
	}
	counts, err := s.inbound.UnreadCounts(ctx, user.ID, box)
	if err != nil {
		return nil, err
	}
	return GetUnreadCounts200JSONResponse(counts), nil
}

// SetMessageCategory is the user's correction of a smart inbox category. By
// default it is remembered for the sender, so their next mail lands correctly.
func (s *Server) SetMessageCategory(ctx context.Context, r SetMessageCategoryRequestObject) (SetMessageCategoryResponseObject, error) {
	fail := func(code int, msg string) (SetMessageCategoryResponseObject, error) {
		return SetMessageCategorydefaultJSONResponse{StatusCode: code, Body: errorBody("category_failed", msg)}, nil
	}
	if r.Body == nil || !inbound.ValidCategory(string(r.Body.Category)) {
		return fail(400, "unknown category")
	}
	ws, _, err := s.scope(ctx, string(r.Slug), workspace.RoleMember)
	if err != nil {
		return fail(404, "message not found")
	}
	msg, err := s.readableMessage(ctx, ws, r.MessageId.String())
	if err != nil {
		return fail(404, "message not found")
	}
	remember := r.Body.RememberSender == nil || *r.Body.RememberSender
	updated, err := s.inbound.SetSenderCategory(ctx, msg.MailboxID, msg.ID, string(r.Body.Category), remember)
	if errors.Is(err, inbound.ErrNoMailbox) {
		return fail(404, "message not found")
	}
	if err != nil {
		return nil, err
	}
	return SetMessageCategory200JSONResponse{Updated: int(updated)}, nil
}
