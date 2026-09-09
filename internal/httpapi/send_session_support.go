package httpapi

import (
	"context"
	"errors"
	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/email"
	"github.com/rnm/heromail/backend/internal/workspace"
	"io"
	"log"
	"mime/multipart"
)

func (s *Server) UploadWorkspaceAttachment(ctx context.Context, request UploadWorkspaceAttachmentRequestObject) (UploadWorkspaceAttachmentResponseObject, error) {
	workspaceID, _, err := s.scope(ctx, request.Slug, workspace.RoleMember)
	if errors.Is(err, workspace.ErrNotFound) {
		return UploadWorkspaceAttachment404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "workspace not found"))}, nil
	}
	if err != nil {
		return nil, err
	}
	if res := s.allow(ctx, workspaceID, uploadQuota()...); !res.Allowed {
		return UploadWorkspaceAttachment429JSONResponse{tooMany(res, "this workspace has reached its upload limit")}, nil
	}
	if request.Body == nil {
		return UploadWorkspaceAttachment400JSONResponse{BadRequestJSONResponse(errorBody("invalid_request", "a multipart body is required"))}, nil
	}

	var part *multipart.Part
	for {
		p, err := request.Body.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return UploadWorkspaceAttachment400JSONResponse{BadRequestJSONResponse(errorBody("invalid_request", "malformed multipart body"))}, nil
		}
		if p.FormName() == "file" {
			part = p
			break
		}
		p.Close()
	}
	if part == nil {
		return UploadWorkspaceAttachment400JSONResponse{BadRequestJSONResponse(errorBody("validation_failed", `a "file" part is required`))}, nil
	}
	defer part.Close()

	filename := part.FileName()
	contentType := part.Header.Get("Content-Type")

	attachment, err := s.emails.UploadAttachment(ctx, workspaceID, filename, contentType, part)
	switch {
	case errors.Is(err, email.ErrStorageNotConfigured):
		return UploadWorkspaceAttachment503JSONResponse(errorBody("storage_not_configured", "attachment storage is not configured on this deployment")), nil
	case errors.Is(err, email.ErrAttachmentTooLarge):
		return UploadWorkspaceAttachment413JSONResponse(errorBody("attachment_too_large", err.Error())), nil
	case errors.Is(err, email.ErrValidation):
		return UploadWorkspaceAttachment400JSONResponse{BadRequestJSONResponse(errorBody("validation_failed", err.Error()))}, nil
	case err != nil:
		log.Printf("upload attachment: %v", err)
		return nil, err
	}
	return UploadWorkspaceAttachment201JSONResponse(attachmentToAPI(attachment)), nil
}

func (s *Server) GetWorkspaceEmail(ctx context.Context, request GetWorkspaceEmailRequestObject) (GetWorkspaceEmailResponseObject, error) {
	workspaceID, _, err := s.scope(ctx, request.Slug, workspace.RoleMember)
	if errors.Is(err, workspace.ErrNotFound) {
		return GetWorkspaceEmail404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "workspace not found"))}, nil
	}
	if err != nil {
		return nil, err
	}

	msg, err := s.emails.ByID(ctx, workspaceID, request.Id.String())
	switch {
	case errors.Is(err, email.ErrNotFound):
		// Another workspace's message lands here too, which is the point.
		return GetWorkspaceEmail404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "email not found"))}, nil
	case err != nil:
		log.Printf("get email: %v", err)
		return nil, err
	}

	userID := ""
	if user, ok := account.CurrentUser(ctx); ok {
		userID = user.ID
	}
	allowed, err := s.inbound.CanReadOutbound(ctx, userID, msg.ID)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return GetWorkspaceEmail404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "email not found"))}, nil
	}

	attachments, err := s.emails.AttachmentsForEmail(ctx, msg.ID)
	if err != nil {
		log.Printf("get email %s: load attachments: %v", msg.ID, err)
		return nil, err
	}
	return GetWorkspaceEmail200JSONResponse(emailToAPI(msg, attachments)), nil
}
