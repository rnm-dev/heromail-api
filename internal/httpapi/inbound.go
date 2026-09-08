package httpapi

import (
	"context"
	"errors"
	"log"
	"strings"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/rnm/heromail/backend/internal/inbound"
	"github.com/rnm/heromail/backend/internal/maildomain"
	"github.com/rnm/heromail/backend/internal/workspace"
)

// Reading mail needs membership; creating an address that will receive it
// needs admin, matching how domains are governed — an address is a claim on
// the domain it sits under.

func (s *Server) ListMailboxes(ctx context.Context, request ListMailboxesRequestObject) (ListMailboxesResponseObject, error) {
	workspaceID, _, err := s.scope(ctx, string(request.Slug), workspace.RoleMember)
	if err != nil {
		return ListMailboxes404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "workspace not found"))}, nil
	}

	boxes, err := s.inbound.MailboxesForWorkspace(ctx, workspaceID)
	if err != nil {
		log.Printf("list mailboxes: %v", err)
		return nil, err
	}

	out := make([]Mailbox, 0, len(boxes))
	for i := range boxes {
		box := mailboxToAPI(&boxes[i])
		allowed := s.domains.AllowsAddress(ctx, workspaceID, boxes[i].Address) == nil
		box.CanSend = &allowed
		out = append(out, box)
	}
	return ListMailboxes200JSONResponse{Mailboxes: out}, nil
}

func (s *Server) CreateMailbox(ctx context.Context, request CreateMailboxRequestObject) (CreateMailboxResponseObject, error) {
	workspaceID, forbidden, err := s.scope(ctx, string(request.Slug), workspace.RoleAdmin)
	if err != nil {
		return CreateMailbox404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "workspace not found"))}, nil
	}
	if forbidden {
		return CreateMailbox403JSONResponse{ForbiddenJSONResponse(errorBody("forbidden", "admin role required"))}, nil
	}
	if request.Body == nil {
		return CreateMailbox400JSONResponse{BadRequestJSONResponse(errorBody("invalid_json", "a JSON body is required"))}, nil
	}

	// The domain is looked up inside the workspace, so an address can only ever
	// be created under a domain this tenant owns.
	domain, err := s.domains.Get(ctx, workspaceID, string(request.Body.Domain))
	if errors.Is(err, maildomain.ErrNotFound) {
		return CreateMailbox404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "domain not found"))}, nil
	}
	if err != nil {
		log.Printf("create mailbox: %v", err)
		return nil, err
	}
	if !domain.Verified() {
		// Receiving for an unproven domain would let anyone who typed a name
		// into the UI intercept somebody else's mail by pointing its MX here.
		return CreateMailbox400JSONResponse{BadRequestJSONResponse(
			errorBody("domain_not_verified", "verify the domain before receiving mail at it"))}, nil
	}

	name := ""
	if request.Body.Name != nil {
		name = *request.Body.Name
	}

	box, err := s.inbound.CreateMailbox(ctx, domain.ID, request.Body.LocalPart, name)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return CreateMailbox409JSONResponse(errorBody("address_taken", "that address already exists")), nil
		}
		log.Printf("create mailbox: %v", err)
		return nil, err
	}
	return CreateMailbox201JSONResponse(mailboxToAPI(box)), nil
}

func (s *Server) ListMessages(ctx context.Context, request ListMessagesRequestObject) (ListMessagesResponseObject, error) {
	workspaceID, _, err := s.scope(ctx, string(request.Slug), workspace.RoleMember)
	if err != nil {
		return ListMessages404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "workspace not found"))}, nil
	}

	// Confirm the mailbox belongs to this workspace before reading its mail,
	// or a member of any workspace could list any other's inbox by id.
	box, err := s.inbound.MailboxByID(ctx, request.MailboxId.String())
	if err != nil || box.WorkspaceID != workspaceID {
		return ListMessages404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "mailbox not found"))}, nil
	}

	limit := 50
	if request.Params.Limit != nil {
		limit = *request.Params.Limit
	}

	msgs, err := s.inbound.ListMessages(ctx, box.ID, limit)
	if err != nil {
		log.Printf("list messages: %v", err)
		return nil, err
	}

	out := make([]ReceivedMessage, 0, len(msgs))
	for i := range msgs {
		out = append(out, receivedMessageToAPI(&msgs[i]))
	}
	return ListMessages200JSONResponse{Messages: out}, nil
}

func (s *Server) GetMessage(ctx context.Context, request GetMessageRequestObject) (GetMessageResponseObject, error) {
	workspaceID, _, err := s.scope(ctx, string(request.Slug), workspace.RoleMember)
	if err != nil {
		return GetMessage404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "workspace not found"))}, nil
	}

	msg, err := s.inbound.MessageByID(ctx, workspaceID, request.MessageId.String())
	if err != nil {
		// Another workspace's message lands here too, which is the point.
		return GetMessage404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "message not found"))}, nil
	}
	return GetMessage200JSONResponse(receivedMessageToAPI(msg)), nil
}

func (s *Server) MarkMessageRead(ctx context.Context, request MarkMessageReadRequestObject) (MarkMessageReadResponseObject, error) {
	workspaceID, _, err := s.scope(ctx, string(request.Slug), workspace.RoleMember)
	if err != nil {
		return MarkMessageRead404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "workspace not found"))}, nil
	}

	msg, err := s.inbound.MarkRead(ctx, workspaceID, request.MessageId.String())
	if err != nil {
		return MarkMessageRead404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "message not found"))}, nil
	}
	return MarkMessageRead200JSONResponse(receivedMessageToAPI(msg)), nil
}

func mailboxToAPI(m *inbound.Mailbox) Mailbox {
	return Mailbox{
		Id:        mustUUID(m.ID),
		Address:   openapi_types.Email(m.Address),
		Name:      m.Name,
		CreatedAt: m.CreatedAt,
	}
}

func receivedMessageToAPI(m *inbound.Message) ReceivedMessage {
	return ReceivedMessage{
		Id:           mustUUID(m.ID),
		MailboxId:    mustUUID(m.MailboxID),
		EnvelopeFrom: &m.EnvelopeFrom,
		EnvelopeTo:   &m.EnvelopeTo,
		MessageId:    m.MessageID,
		From:         m.FromAddr,
		FromName:     m.FromName,
		Subject:      m.Subject,
		SentAt:       m.SentAt,
		Text:         m.TextBody,
		Html:         m.HTMLBody,
		SizeBytes:    m.SizeBytes,
		ReadAt:       m.ReadAt,
		ReceivedAt:   m.ReceivedAt,
	}
}
