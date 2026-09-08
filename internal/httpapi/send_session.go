package httpapi

import (
	"context"
	"errors"
	"log"
	"strings"

	"github.com/rnm/heromail/backend/internal/email"
	"github.com/rnm/heromail/backend/internal/workspace"
)

// SendWorkspaceEmail is the same pipeline as SendEmail, reached with a session.
//
// The browser holds a session, not a workspace key, and putting a key into a
// page to work around that would leak a credential that grants the whole
// workspace. So membership authorises this one, and the workspace comes from
// the path rather than from a credential that encodes exactly one.
func (s *Server) SendWorkspaceEmail(ctx context.Context, request SendWorkspaceEmailRequestObject) (SendWorkspaceEmailResponseObject, error) {
	workspaceID, _, err := s.scope(ctx, string(request.Slug), workspace.RoleMember)
	if errors.Is(err, workspace.ErrNotFound) {
		return SendWorkspaceEmail404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "workspace not found"))}, nil
	}
	if err != nil {
		return nil, err
	}
	if request.Body == nil {
		return SendWorkspaceEmail400JSONResponse{BadRequestJSONResponse(errorBody("invalid_json", "a JSON body is required"))}, nil
	}

	// Every member can send as a shared mailbox in this workspace; arbitrary
	// addresses, even on an owned domain, are not browser sending identities.
	boxes, err := s.inbound.MailboxesForWorkspace(ctx, workspaceID)
	if err != nil {
		return nil, err
	}
	from := strings.ToLower(strings.TrimSpace(string(request.Body.From)))
	allowed := false
	for _, box := range boxes {
		if strings.EqualFold(box.Address, from) {
			allowed = true
			break
		}
	}
	at := strings.LastIndex(from, "@")
	if !allowed || at < 0 {
		return SendWorkspaceEmail400JSONResponse{BadRequestJSONResponse(errorBody("sender_not_allowed", "choose an existing mailbox in this workspace"))}, nil
	}
	if err := s.domains.AllowsAddress(ctx, workspaceID, from); err != nil {
		return SendWorkspaceEmail400JSONResponse{BadRequestJSONResponse(errorBody("sender_not_allowed", "verify the sender domain before sending"))}, nil
	}

	// The same per-workspace quota as the API-key path, keyed the same way:
	// the hazard is a tenant burning shared sending reputation, and which
	// credential they used to do it makes no difference.
	if res := s.allow(ctx, workspaceID, sendQuota()...); !res.Allowed {
		return SendWorkspaceEmail429JSONResponse{tooMany(res, "this workspace has reached its send limit")}, nil
	}

	idempotencyKey := ""
	if request.Params.IdempotencyKey != nil {
		idempotencyKey = *request.Params.IdempotencyKey
	}

	to := make([]string, 0, len(request.Body.To))
	for _, addr := range request.Body.To {
		to = append(to, string(addr))
	}

	var attachmentIDs []string
	if request.Body.Attachments != nil {
		attachmentIDs = make([]string, 0, len(*request.Body.Attachments))
		for _, id := range *request.Body.Attachments {
			attachmentIDs = append(attachmentIDs, id.String())
		}
	}

	msg, err := s.emails.Send(ctx, workspaceID, idempotencyKey, email.SendRequest{
		From:          from,
		To:            to,
		Cc:            emailAddresses(request.Body.Cc),
		Bcc:           emailAddresses(request.Body.Bcc),
		Subject:       deref(request.Body.Subject),
		HTML:          deref(request.Body.Html),
		Text:          deref(request.Body.Text),
		AttachmentIDs: attachmentIDs,
	})
	switch {
	case errors.Is(err, email.ErrValidation),
		errors.Is(err, email.ErrNotFound),
		errors.Is(err, email.ErrAttachmentNotFound),
		errors.Is(err, email.ErrAttachmentsTooLarge),
		errors.Is(err, email.ErrFromNotAllowed):
		return SendWorkspaceEmail400JSONResponse{BadRequestJSONResponse(errorBody("validation_failed", err.Error()))}, nil
	case errors.Is(err, email.ErrEnqueueFailed):
		log.Printf("send workspace email %s: %v", msg.ID, err)
		return nil, err
	case err != nil:
		log.Printf("send workspace email: %v", err)
		return nil, err
	}
	return SendWorkspaceEmail202JSONResponse{Id: mustUUID(msg.ID), Status: EmailStatus(msg.Status)}, nil
}
