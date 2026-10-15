package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/workspace"
)

const draftColumns = `d.id, w.slug, d.version, d.data, d.updated_at`

func scanDraft(row pgx.Row) (MailDraft, error) {
	var d MailDraft
	err := row.Scan(&d.Id, &d.Workspace, &d.Version, &d.Data, &d.UpdatedAt)
	return d, err
}
func (s *Server) ListDrafts(ctx context.Context, r ListDraftsRequestObject) (ListDraftsResponseObject, error) {
	user, _ := account.CurrentUser(ctx)
	offset := 0
	if r.Params.Offset != nil {
		offset = *r.Params.Offset
	}
	if offset < 0 {
		return ListDrafts400JSONResponse{BadRequestJSONResponse(errorBody("validation_failed", "invalid offset"))}, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT `+draftColumns+` FROM mail_drafts d JOIN workspaces w ON w.id=d.workspace_id JOIN workspace_members m ON m.workspace_id=w.id AND m.user_id=d.user_id WHERE d.user_id=$1 ORDER BY d.updated_at DESC,d.id DESC LIMIT 51 OFFSET $2`, user.ID, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MailDraft{}
	for rows.Next() {
		d, err := scanDraft(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	more := len(out) > 50
	if more {
		out = out[:50]
	}
	return ListDrafts200JSONResponse{Drafts: out, HasMore: more}, nil
}
func (s *Server) GetDraft(ctx context.Context, r GetDraftRequestObject) (GetDraftResponseObject, error) {
	ws, _, err := s.scope(ctx, r.Slug, workspace.RoleMember)
	if errors.Is(err, workspace.ErrNotFound) {
		return GetDraft404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "draft not found"))}, nil
	}
	if err != nil {
		return nil, err
	}
	user, _ := account.CurrentUser(ctx)
	d, err := scanDraft(s.pool.QueryRow(ctx, `SELECT `+draftColumns+` FROM mail_drafts d JOIN workspaces w ON w.id=d.workspace_id WHERE d.id=$1 AND d.workspace_id=$2 AND d.user_id=$3`, r.Id, ws, user.ID))
	if errors.Is(err, pgx.ErrNoRows) {
		return GetDraft404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "draft not found"))}, nil
	}
	if err != nil {
		return nil, err
	}
	return GetDraft200JSONResponse(d), nil
}

// Validate persisted editor state so data loaded on another device has the same
// types as local state. Attachments remain private to their uploading person.
func (s *Server) validateDraft(ctx context.Context, tx pgx.Tx, ws, user string, data map[string]interface{}) error {
	encoded, _ := json.Marshal(data)
	if len(encoded) > 1024*1024 {
		return fmt.Errorf("draft exceeds 1 MiB")
	}
	stringsAllowed := map[string]bool{"workspace": true, "from": true, "to": true, "cc": true, "bcc": true, "subject": true, "body": true, "bodyHtml": true, "replyToMessageId": true, "forwardMessageId": true}
	bools := map[string]bool{"mailing": true, "richText": true, "replyAll": true, "includeOriginal": true}
	for key, value := range data {
		if stringsAllowed[key] {
			if _, ok := value.(string); !ok {
				return fmt.Errorf("invalid %s", key)
			}
			continue
		}
		if bools[key] {
			if _, ok := value.(bool); !ok {
				return fmt.Errorf("invalid %s", key)
			}
			continue
		}
		if key != "attachments" && key != "attempt" && key != "originalUpload" {
			return fmt.Errorf("unsupported field %s", key)
		}
	}
	ids := map[string]bool{}
	if v, ok := data["attachments"]; ok {
		files, ok := v.([]interface{})
		if !ok || len(files) > 20 {
			return fmt.Errorf("at most 20 attachments")
		}
		for _, f := range files {
			file, ok := f.(map[string]interface{})
			if !ok {
				return fmt.Errorf("invalid attachment")
			}
			id, ok := file["upload"].(string)
			if !ok {
				return fmt.Errorf("attachment must be uploaded")
			}
			meta, ok := file["file"].(map[string]interface{})
			if !ok {
				return fmt.Errorf("invalid file")
			}
			if _, ok := meta["name"].(string); !ok {
				return fmt.Errorf("invalid filename")
			}
			if size, ok := meta["size"].(float64); !ok || size < 0 {
				return fmt.Errorf("invalid file size")
			}
			ids[id] = true
		}
	}
	if original, ok := data["originalUpload"]; ok && original != nil {
		obj, ok := original.(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid original")
		}
		id, ok := obj["id"].(string)
		if !ok {
			return fmt.Errorf("invalid original id")
		}
		ids[id] = true
	}
	if pending, ok := data["attempt"]; ok && pending != nil {
		obj, ok := pending.(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid send attempt")
		}
		key, ok := obj["key"].(string)
		if !ok || len(key) > 100 || key == "" {
			return fmt.Errorf("invalid send key")
		}
		if obj["workspace"] != data["workspace"] {
			return fmt.Errorf("invalid send workspace")
		}
		payload, ok := obj["payload"].(map[string]interface{})
		if !ok {
			return fmt.Errorf("invalid send payload")
		}
		encoded, _ := json.Marshal(payload)
		var send SendEmailRequest
		if err := json.Unmarshal(encoded, &send); err != nil || send.From == "" || len(send.To) == 0 {
			return fmt.Errorf("invalid send payload")
		}
		if mailing, exists := obj["mailing"]; exists {
			enabled, ok := mailing.(bool)
			if !ok || (enabled && send.Bcc == nil) {
				return fmt.Errorf("invalid mailing attempt")
			}
		}
		if files, ok := payload["attachments"].([]interface{}); ok {
			for _, f := range files {
				id, ok := f.(string)
				if !ok {
					return fmt.Errorf("invalid attachment id")
				}
				ids[id] = true
			}
		}
	}
	if len(ids) > 20 {
		return fmt.Errorf("at most 20 attachments")
	}
	for id := range ids {
		if _, err := uuid.Parse(id); err != nil {
			return fmt.Errorf("invalid attachment id")
		}
		var ok bool
		err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM attachments WHERE id=$1 AND workspace_id=$2 AND upload_owner_id=$3 AND email_id IS NULL)`, id, ws, user).Scan(&ok)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("attachment unavailable")
		}
	}
	return nil
}
func (s *Server) SaveDraft(ctx context.Context, r SaveDraftRequestObject) (SaveDraftResponseObject, error) {
	ws, _, err := s.scope(ctx, r.Slug, workspace.RoleMember)
	if errors.Is(err, workspace.ErrNotFound) {
		return SaveDraft404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "workspace not found"))}, nil
	}
	if err != nil {
		return nil, err
	}
	if r.Body == nil || r.Body.Version < 0 {
		return SaveDraft400JSONResponse{BadRequestJSONResponse(errorBody("validation_failed", "version and data required"))}, nil
	}
	user, _ := account.CurrentUser(ctx)
	// Serialise writes by draft id, including the initial insert. It also makes
	// retrying a save whose response was lost return the identical version.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, r.Id.String()); err != nil {
		return nil, err
	}
	d, err := scanDraft(tx.QueryRow(ctx, `SELECT `+draftColumns+` FROM mail_drafts d JOIN workspaces w ON w.id=d.workspace_id WHERE d.id=$1 AND d.workspace_id=$2 AND d.user_id=$3 FOR UPDATE OF d`, r.Id, ws, user.ID))
	exists := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	data := r.Body.Data
	if data == nil {
		data = map[string]interface{}{}
	}
	data["workspace"] = r.Slug
	encoded, _ := json.Marshal(data)
	old, _ := json.Marshal(d.Data)
	if exists && d.Version == r.Body.Version+1 && string(encoded) == string(old) {
		return SaveDraft200JSONResponse(d), nil
	}
	if (exists && (d.Version != r.Body.Version || d.Data["attempt"] != nil)) || (!exists && r.Body.Version != 0) {
		return SaveDraft409JSONResponse(errorBody("draft_conflict", "Черновик изменён на другом устройстве или уже отправляется. Откройте серверную версию через список черновиков; локальный текст сохранён.")), nil
	}
	if err = s.validateDraft(ctx, tx, ws, user.ID, data); err != nil {
		return SaveDraft400JSONResponse{BadRequestJSONResponse(errorBody("validation_failed", err.Error()))}, nil
	}
	if !exists {
		if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,1))`, user.ID); err != nil {
			return nil, err
		}
		var count int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM mail_drafts WHERE user_id=$1`, user.ID).Scan(&count); err != nil {
			return nil, err
		}
		if count >= 500 {
			return SaveDraft400JSONResponse{BadRequestJSONResponse(errorBody("draft_limit", "Можно сохранить до 500 черновиков. Удалите ненужные."))}, nil
		}
		tag, err := tx.Exec(ctx, `INSERT INTO mail_drafts(id,workspace_id,user_id,data) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, r.Id, ws, user.ID, encoded)
		if err != nil {
			return nil, err
		}
		if tag.RowsAffected() == 0 {
			return SaveDraft404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "draft not found"))}, nil
		}
	} else {
		if _, err = tx.Exec(ctx, `UPDATE mail_drafts SET data=$2,version=version+1,updated_at=now() WHERE id=$1`, r.Id, encoded); err != nil {
			return nil, err
		}
	}
	d, err = scanDraft(tx.QueryRow(ctx, `SELECT `+draftColumns+` FROM mail_drafts d JOIN workspaces w ON w.id=d.workspace_id WHERE d.id=$1`, r.Id))
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return SaveDraft200JSONResponse(d), nil
}
func (s *Server) DeleteDraft(ctx context.Context, r DeleteDraftRequestObject) (DeleteDraftResponseObject, error) {
	ws, _, err := s.scope(ctx, r.Slug, workspace.RoleMember)
	if errors.Is(err, workspace.ErrNotFound) {
		return DeleteDraft404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "draft not found"))}, nil
	}
	if err != nil {
		return nil, err
	}
	user, _ := account.CurrentUser(ctx)
	tag, err := s.pool.Exec(ctx, `DELETE FROM mail_drafts WHERE id=$1 AND workspace_id=$2 AND user_id=$3 AND version=$4`, r.Id, ws, user.ID, r.Params.Version)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if err = s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mail_drafts WHERE id=$1 AND workspace_id=$2 AND user_id=$3)`, r.Id, ws, user.ID).Scan(&exists); err != nil {
			return nil, err
		}
		if exists {
			return DeleteDraft409JSONResponse(errorBody("draft_conflict", "Черновик изменён на другом устройстве. Обновите список.")), nil
		}
		return DeleteDraft404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "draft not found"))}, nil
	}
	return DeleteDraft204Response{}, nil
}
