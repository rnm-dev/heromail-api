package httpapi

import (
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/workspace"
)

func (s *Server) ListMailSignatures(ctx context.Context, r ListMailSignaturesRequestObject) (ListMailSignaturesResponseObject, error) {
	ws, _, err := s.scope(ctx, r.Slug, workspace.RoleMember)
	if errors.Is(err, workspace.ErrNotFound) {
		return ListMailSignatures404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "workspace not found"))}, nil
	}
	if err != nil {
		return nil, err
	}
	user, _ := account.CurrentUser(ctx)
	boxes, err := s.inbound.MailboxesForWorkspace(ctx, ws)
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(boxes))
	for i, box := range boxes {
		ids[i] = box.ID
	}
	readable, err := s.inbound.AccessibleMailboxes(ctx, user.ID, ids)
	if err != nil {
		return nil, err
	}
	allowed := []string{}
	for _, box := range boxes {
		if readable[box.ID] {
			allowed = append(allowed, strings.ToLower(box.Address))
		}
	}
	rows, err := s.pool.Query(ctx, `SELECT sender,text_body,version FROM mail_signatures WHERE workspace_id=$1 AND user_id=$2 AND sender=ANY($3) ORDER BY sender`, ws, user.ID, allowed)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []MailSignature{}
	for rows.Next() {
		var sig MailSignature
		if err := rows.Scan(&sig.Sender, &sig.Text, &sig.Version); err != nil {
			return nil, err
		}
		result = append(result, sig)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ListMailSignatures200JSONResponse{Signatures: result}, nil
}
func (s *Server) SaveMailSignature(ctx context.Context, r SaveMailSignatureRequestObject) (SaveMailSignatureResponseObject, error) {
	ws, _, err := s.scope(ctx, r.Slug, workspace.RoleMember)
	if errors.Is(err, workspace.ErrNotFound) {
		return SaveMailSignature404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "workspace not found"))}, nil
	}
	if err != nil {
		return nil, err
	}
	if r.Body == nil || r.Body.Version < 0 || utf8.RuneCountInString(r.Body.Text) > 10000 {
		return SaveMailSignature400JSONResponse{BadRequestJSONResponse(errorBody("validation_failed", "signature must be at most 10000 characters; version required"))}, nil
	}
	user, _ := account.CurrentUser(ctx)
	sender := strings.ToLower(strings.TrimSpace(string(r.Body.Sender)))
	boxes, err := s.inbound.MailboxesForWorkspace(ctx, ws)
	if err != nil {
		return nil, err
	}
	allowed := false
	for _, box := range boxes {
		if strings.EqualFold(box.Address, sender) {
			allowed, err = s.inbound.CanAccess(ctx, user.ID, box.ID)
			if err != nil {
				return nil, err
			}
			break
		}
	}
	if !allowed {
		return SaveMailSignature404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "sender not found"))}, nil
	}
	// Atomic optimistic update. Repeating an identical previous-version write
	// recovers a lost response without changing the version a second time.
	var sig MailSignature
	err = s.pool.QueryRow(ctx, `INSERT INTO mail_signatures(workspace_id,user_id,sender,text_body,version)
 SELECT $1,$2,$3,$4,1 WHERE $5=0
 ON CONFLICT(workspace_id,user_id,sender) DO NOTHING RETURNING sender,text_body,version`, ws, user.ID, sender, r.Body.Text, r.Body.Version).Scan(&sig.Sender, &sig.Text, &sig.Version)
	if errors.Is(err, pgx.ErrNoRows) {
		err = s.pool.QueryRow(ctx, `UPDATE mail_signatures SET text_body=$4,version=CASE WHEN version=$5 THEN version+1 ELSE version END
 WHERE workspace_id=$1 AND user_id=$2 AND sender=$3 AND (version=$5 OR (version=$5+1 AND text_body=$4))
 RETURNING sender,text_body,version`, ws, user.ID, sender, r.Body.Text, r.Body.Version).Scan(&sig.Sender, &sig.Text, &sig.Version)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return SaveMailSignature409JSONResponse(errorBody("signature_conflict", "Подпись изменена на другом устройстве. Обновите её перед сохранением.")), nil
	}
	if err != nil {
		return nil, err
	}
	return SaveMailSignature200JSONResponse(sig), nil
}
