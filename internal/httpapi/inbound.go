package httpapi

import (
	"context"
	"errors"
	"log"
	"strings"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/rnm/heromail/backend/internal/account"
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

	user, _ := account.CurrentUser(ctx)
	role, err := s.workspaces.MembershipRole(ctx, workspaceID, user.ID)
	if err != nil {
		return nil, err
	}
	out := make([]Mailbox, 0, len(boxes))
	for i := range boxes {
		canRead, err := s.inbound.CanAccess(ctx, user.ID, boxes[i].ID)
		if err != nil {
			return nil, err
		}
		if !canRead && !role.AtLeast(workspace.RoleAdmin) {
			continue
		}
		box := mailboxToAPI(&boxes[i])
		box.CanRead = &canRead
		allowed := canRead && s.domains.AllowsAddress(ctx, workspaceID, boxes[i].Address) == nil
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

	user, _ := account.CurrentUser(ctx)
	var owner *string
	if request.Body.Shared == nil || !*request.Body.Shared {
		id := user.ID
		owner = &id
	}
	if request.Body.OwnerUserId != nil {
		id := request.Body.OwnerUserId.String()
		owner = &id
	}
	if owner != nil {
		if _, err := s.workspaces.MembershipRole(ctx, workspaceID, *owner); err != nil {
			return CreateMailbox400JSONResponse{BadRequestJSONResponse(errorBody("invalid_owner", "owner must be a workspace member"))}, nil
		}
	}
	box, err := s.inbound.CreateMailbox(ctx, domain.ID, request.Body.LocalPart, name, owner)
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
	user, _ := account.CurrentUser(ctx)
	allowed := false
	if err == nil {
		allowed, err = s.inbound.CanAccess(ctx, user.ID, box.ID)
	}
	if err != nil || !allowed || box.WorkspaceID != workspaceID {
		return ListMessages404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "mailbox not found"))}, nil
	}

	limit := 50
	if request.Params.Limit != nil {
		limit = *request.Params.Limit
	}

	offset := 0
	if request.Params.Offset != nil {
		offset = *request.Params.Offset
	}
	folder := "INBOX"
	if request.Params.Folder != nil {
		folder = string(*request.Params.Folder)
	}
	if folder != "INBOX" && folder != "Junk" {
		return ListMessages404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "folder not found"))}, nil
	}
	// A blank q is not a search for nothing — it is the unfiltered folder, which
	// is what the mail client shows when the search box is emptied.
	search := ""
	if request.Params.Q != nil {
		search = strings.TrimSpace(*request.Params.Q)
	}

	var msgs []inbound.Message
	if search != "" {
		msgs, err = s.inbound.SearchFolderMessages(ctx, box.ID, folder, search, limit, offset)
	} else {
		msgs, err = s.inbound.ListFolderMessages(ctx, box.ID, folder, limit, offset)
	}
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

	msg, err := s.readableMessage(ctx, workspaceID, request.MessageId.String())
	if err != nil {
		// Another workspace's message lands here too, which is the point.
		return GetMessage404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "message not found"))}, nil
	}
	presentation, err := s.inbound.Presentation(ctx, msg.MailboxID, msg.ID)
	if err != nil {
		return nil, err
	}
	out := receivedMessageToAPI(msg)
	out.ReplyTo = &presentation.ReplyTo
	out.InlineMedia = &presentation.InlineMedia
	out.InlineMediaOmitted = &presentation.Omitted
	return GetMessage200JSONResponse(out), nil
}

func (s *Server) MarkMessageRead(ctx context.Context, request MarkMessageReadRequestObject) (MarkMessageReadResponseObject, error) {
	workspaceID, _, err := s.scope(ctx, string(request.Slug), workspace.RoleMember)
	if err != nil {
		return MarkMessageRead404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "workspace not found"))}, nil
	}

	if _, err := s.readableMessage(ctx, workspaceID, request.MessageId.String()); err != nil {
		return MarkMessageRead404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "message not found"))}, nil
	}
	msg, err := s.inbound.MarkRead(ctx, workspaceID, request.MessageId.String())
	if err != nil {
		return MarkMessageRead404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "message not found"))}, nil
	}
	return MarkMessageRead200JSONResponse(receivedMessageToAPI(msg)), nil
}

func mailboxToAPI(m *inbound.Mailbox) Mailbox {
	var owner *openapi_types.UUID
	if m.OwnerUserID != nil {
		id := mustUUID(*m.OwnerUserID)
		owner = &id
	}
	return Mailbox{
		SmtpPasswordSet: &m.SMTPPasswordSet,
		OwnerUserId:     owner,
		Id:              mustUUID(m.ID),
		Address:         openapi_types.Email(m.Address),
		Name:            m.Name,
		CreatedAt:       m.CreatedAt,
	}
}

func receivedMessageToAPI(m *inbound.Message) ReceivedMessage {
	return ReceivedMessage{
		Folder:       m.Folder,
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

func (s *Server) readableMessage(ctx context.Context, workspaceID, id string) (*inbound.Message, error) {
	msg, err := s.inbound.MessageByID(ctx, workspaceID, id)
	if err != nil {
		return nil, err
	}
	user, ok := account.CurrentUser(ctx)
	if !ok {
		return nil, inbound.ErrNoMailbox
	}
	allowed, err := s.inbound.CanAccess(ctx, user.ID, msg.MailboxID)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return nil, inbound.ErrNoMailbox
	}
	return msg, nil
}

func (s *Server) AssignMailboxOwner(ctx context.Context, r AssignMailboxOwnerRequestObject) (AssignMailboxOwnerResponseObject, error) {
	fail := func(code int, msg string) (AssignMailboxOwnerResponseObject, error) {
		return AssignMailboxOwnerdefaultJSONResponse{StatusCode: code, Body: errorBody("assignment_failed", msg)}, nil
	}
	ws, forbidden, err := s.scope(ctx, r.Slug, workspace.RoleOwner)
	if err != nil {
		return fail(404, "workspace not found")
	}
	if forbidden {
		return fail(403, "only the workspace owner can assign mailboxes")
	}
	if r.Body == nil {
		return fail(400, "owner_user_id is required")
	}
	var owner *string
	if r.Body.OwnerUserId != nil {
		id := r.Body.OwnerUserId.String()
		owner = &id
	}
	if err := s.inbound.AssignOwner(ctx, ws, r.MailboxId.String(), owner); err != nil {
		return fail(400, err.Error())
	}
	box, err := s.inbound.MailboxByID(ctx, r.MailboxId.String())
	if err != nil {
		return nil, err
	}
	return AssignMailboxOwner200JSONResponse(mailboxToAPI(box)), nil
}

func (s *Server) MoveReceivedMessage(ctx context.Context, r MoveReceivedMessageRequestObject) (MoveReceivedMessageResponseObject, error) {
	fail := func(code int, msg string) (MoveReceivedMessageResponseObject, error) {
		return MoveReceivedMessagedefaultJSONResponse{StatusCode: code, Body: errorBody("move_failed", msg)}, nil
	}
	if r.Body == nil || (string(r.Body.Folder) != "INBOX" && string(r.Body.Folder) != "Junk") {
		return fail(400, "folder must be INBOX or Junk")
	}
	ws, _, err := s.scope(ctx, string(r.Slug), workspace.RoleMember)
	if err != nil {
		return fail(404, "message not found")
	}
	msg, err := s.readableMessage(ctx, ws, r.MessageId.String())
	if err != nil {
		return fail(404, "message not found")
	}
	moved, err := s.inbound.MoveMessage(ctx, msg.MailboxID, msg.ID, string(r.Body.Folder))
	if err != nil {
		return nil, err
	}
	return MoveReceivedMessage200JSONResponse(receivedMessageToAPI(moved)), nil
}
