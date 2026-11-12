package httpapi

import (
	"context"
	"errors"
	"log"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/inbound"
	"github.com/rnm/heromail/backend/internal/workspace"
)

func (s *Server) ListMailboxChanges(ctx context.Context, request ListMailboxChangesRequestObject) (ListMailboxChangesResponseObject, error) {
	notFound := ListMailboxChanges404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "mailbox not found"))}
	workspaceID, _, err := s.scope(ctx, string(request.Slug), workspace.RoleMember)
	if err != nil {
		return notFound, nil
	}
	// Same gate as the message list: the mailbox must be in this workspace
	// and readable by this user.
	box, err := s.inbound.MailboxByID(ctx, request.MailboxId.String())
	user, _ := account.CurrentUser(ctx)
	allowed := false
	if err == nil {
		allowed, err = s.inbound.CanAccess(ctx, user.ID, box.ID)
	}
	if err != nil || !allowed || box.WorkspaceID != workspaceID {
		return notFound, nil
	}

	limit := 200
	if request.Params.Limit != nil {
		limit = *request.Params.Limit
	}
	if limit < 1 || limit > 500 {
		return ListMailboxChanges400JSONResponse{BadRequestJSONResponse(errorBody("validation_failed", "limit must be between 1 and 500"))}, nil
	}

	changes, err := s.inbound.Changes(ctx, box.ID, deref(request.Params.Cursor), limit)
	switch {
	case errors.Is(err, inbound.ErrCursorExpired):
		return ListMailboxChanges410JSONResponse(errorBody("cursor_expired", "the sync cursor is no longer valid; resync from scratch")), nil
	case err != nil:
		log.Printf("mailbox changes: %v", err)
		return nil, err
	}

	out := MailboxChanges{
		Messages:            make([]ChangedMessage, 0, len(changes.Messages)),
		Deleted:             make([]openapi_types.UUID, 0, len(changes.Deleted)),
		NextCursor:          changes.NextCursor,
		HasMore:             changes.HasMore,
		OrganizationChanged: changes.OrganizationChanged,
		Unread:              changes.Unread,
	}
	for i := range changes.Messages {
		c := &changes.Messages[i]
		card := receivedMessageToAPI(&c.Message)
		// Compact: the HTML part is fetched when the message is opened.
		card.Html = nil
		if request.Params.Compact != nil && *request.Params.Compact {
			card.Text = nil
		}
		labels := make([]openapi_types.UUID, 0, len(c.LabelIDs))
		for _, id := range c.LabelIDs {
			labels = append(labels, mustUUID(id))
		}
		out.Messages = append(out.Messages, ChangedMessage{Message: card, LabelIds: labels})
	}
	for _, id := range changes.Deleted {
		out.Deleted = append(out.Deleted, mustUUID(id))
	}
	return ListMailboxChanges200JSONResponse(out), nil
}
