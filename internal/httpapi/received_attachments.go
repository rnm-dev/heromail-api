package httpapi

import (
	"context"
	"mime"
	"net/http"
	"strconv"

	"github.com/rnm/heromail/backend/internal/workspace"
)

type attachmentDownload struct {
	filename string
	data     []byte
}

func (r attachmentDownload) VisitDownloadReceivedAttachmentResponse(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": r.filename}))
	w.Header().Set("Content-Length", strconv.Itoa(len(r.data)))
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write(r.data)
	return err
}
func (s *Server) DownloadReceivedAttachment(ctx context.Context, r DownloadReceivedAttachmentRequestObject) (DownloadReceivedAttachmentResponseObject, error) {
	missing := DownloadReceivedAttachment404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "attachment not found"))}
	ws, _, err := s.scope(ctx, string(r.Slug), workspace.RoleMember)
	if err != nil {
		return missing, nil
	}
	msg, err := s.readableMessage(ctx, ws, r.MessageId.String())
	if err != nil {
		return missing, nil
	}
	item, data, err := s.inbound.Attachment(ctx, msg.MailboxID, msg.ID, r.AttachmentId)
	if err != nil {
		return missing, nil
	}
	return attachmentDownload{filename: item.Filename, data: data}, nil
}

func (r attachmentDownload) VisitDownloadReceivedRawResponse(w http.ResponseWriter) error {
	return r.VisitDownloadReceivedAttachmentResponse(w)
}

func (s *Server) DownloadReceivedRaw(ctx context.Context, r DownloadReceivedRawRequestObject) (DownloadReceivedRawResponseObject, error) {
	missing := DownloadReceivedRaw404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "message not found"))}
	ws, _, err := s.scope(ctx, string(r.Slug), workspace.RoleMember)
	if err != nil {
		return missing, nil
	}
	msg, err := s.readableMessage(ctx, ws, r.MessageId.String())
	if err != nil {
		return missing, nil
	}
	var raw []byte
	if err = s.pool.QueryRow(ctx, `SELECT raw FROM messages WHERE id=$1 AND mailbox_id=$2`, msg.ID, msg.MailboxID).Scan(&raw); err != nil {
		return nil, err
	}
	return attachmentDownload{filename: "original.eml", data: raw}, nil
}
