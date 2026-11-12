package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"mime"
	"net/http"
	"time"

	"github.com/rnm/heromail/backend/internal/workspace"
)

type attachmentDownload struct {
	filename, contentType string
	data                  []byte
	// req carries Range / If-Range / If-None-Match. Strict handlers only see
	// a context, so withRequestContext stashes it there.
	req *http.Request
}

// Visit serves the bytes with http.ServeContent: Range (single and multiple,
// 206 / 416), If-Range and If-None-Match against a content ETag, and HEAD.
// Messages are immutable, so the ETag of a part never changes.
func (r attachmentDownload) VisitDownloadReceivedAttachmentResponse(w http.ResponseWriter) error {
	contentType := r.contentType
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	sum := sha256.Sum256(r.data)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": r.filename}))
	w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:16])+`"`)
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	req := r.req
	if req == nil {
		req = &http.Request{Method: http.MethodGet, Header: http.Header{}}
	}
	http.ServeContent(w, req, "", time.Time{}, bytes.NewReader(r.data))
	return nil
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
	return attachmentDownload{filename: item.Filename, contentType: item.DownloadContentType(), data: data, req: httpRequestFrom(ctx)}, nil
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
	return attachmentDownload{filename: "original.eml", data: raw, req: httpRequestFrom(ctx)}, nil
}
