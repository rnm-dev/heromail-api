package httpapi

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/workspace"
	"golang.org/x/crypto/bcrypt"
)

// Explicit owner-only delegation of sending rights. It grants no reading rights
// and does not reset an employee's account password or mandatory-password flag.
func (s *Server) SetMailboxSMTPPassword(ctx context.Context, r SetMailboxSMTPPasswordRequestObject) (SetMailboxSMTPPasswordResponseObject, error) {
	fail := func(code int, msg string) (SetMailboxSMTPPasswordResponseObject, error) {
		return SetMailboxSMTPPassworddefaultJSONResponse{StatusCode: code, Body: errorBody("smtp_password_failed", msg)}, nil
	}
	ws, forbidden, err := s.scope(ctx, r.Slug, workspace.RoleOwner)
	if err != nil {
		return fail(404, "workspace not found")
	}
	if forbidden {
		return fail(403, "only the workspace owner can manage SMTP passwords")
	}
	if r.Body == nil {
		return fail(400, "password is required")
	}
	pass := deref(r.Body.Password)
	if utf8.RuneCountInString(pass) < 12 || len(pass) > 72 || strings.TrimSpace(pass) == "" || strings.ContainsAny(pass, "\r\n\x00") {
		return fail(400, "use at least 12 characters and at most 72 UTF-8 bytes")
	}
	user, _ := account.CurrentUser(ctx)
	box, err := s.inbound.MailboxByID(ctx, r.MailboxId.String())
	if err != nil || box.WorkspaceID != ws {
		return fail(404, "mailbox not found")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	if err = s.inbound.SetSMTPPassword(ctx, ws, box.ID, user.ID, string(hash)); err != nil {
		return fail(404, "mailbox or workspace owner no longer available")
	}
	return SetMailboxSMTPPassword204Response{}, nil
}
func (s *Server) DeleteMailboxSMTPPassword(ctx context.Context, r DeleteMailboxSMTPPasswordRequestObject) (DeleteMailboxSMTPPasswordResponseObject, error) {
	fail := func(code int, msg string) (DeleteMailboxSMTPPasswordResponseObject, error) {
		return DeleteMailboxSMTPPassworddefaultJSONResponse{StatusCode: code, Body: errorBody("smtp_password_failed", msg)}, nil
	}
	ws, forbidden, err := s.scope(ctx, r.Slug, workspace.RoleOwner)
	if err != nil {
		return fail(404, "workspace not found")
	}
	if forbidden {
		return fail(403, "only the workspace owner can manage SMTP passwords")
	}
	box, err := s.inbound.MailboxByID(ctx, r.MailboxId.String())
	if err != nil || box.WorkspaceID != ws {
		return fail(404, "mailbox not found")
	}
	if err = s.inbound.DeleteSMTPPassword(ctx, ws, box.ID); err != nil {
		return nil, err
	}
	return DeleteMailboxSMTPPassword204Response{}, nil
}
