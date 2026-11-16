package httpapi

import (
	"context"
	"log"
	"net/http"

	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/inbound"
	"github.com/rnm/heromail/backend/internal/workspace"
)

func (r attachmentDownload) VisitDownloadSentAttachmentResponse(w http.ResponseWriter) error {
	return r.VisitDownloadReceivedAttachmentResponse(w)
}

// DownloadSentAttachment serves a file of an outgoing message to whoever may
// read that message (GetWorkspaceEmail's rule). Every miss is the same 404.
func (s *Server) DownloadSentAttachment(ctx context.Context, r DownloadSentAttachmentRequestObject) (DownloadSentAttachmentResponseObject, error) {
	missing := DownloadSentAttachment404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "attachment not found"))}
	ws, _, err := s.scope(ctx, r.Slug, workspace.RoleMember)
	if err != nil {
		return missing, nil
	}
	msg, err := s.emails.ByID(ctx, ws, r.Id.String())
	if err != nil {
		return missing, nil
	}
	userID := ""
	if user, ok := account.CurrentUser(ctx); ok {
		userID = user.ID
	}
	if allowed, err := s.inbound.CanReadOutbound(ctx, userID, msg.ID); err != nil {
		return nil, err
	} else if !allowed {
		return missing, nil
	}
	item, data, err := s.emails.AttachmentContent(ctx, msg.ID, r.AttachmentId.String())
	if err != nil {
		log.Printf("download sent attachment %s/%s: %v", msg.ID, r.AttachmentId, err)
		return missing, nil
	}
	return attachmentDownload{filename: item.Filename, contentType: inbound.DownloadContentType(item.ContentType), data: data, req: httpRequestFrom(ctx)}, nil
}
