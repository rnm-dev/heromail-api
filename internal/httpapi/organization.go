package httpapi

import (
	"context"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/inbound"
	"github.com/rnm/heromail/backend/internal/workspace"
)

type organizationError struct {
	code    int
	message string
}

func (e organizationError) Error() string { return e.message }
func organizationFailure(err error) (int, Error) {
	var e organizationError
	if errors.As(err, &e) {
		return e.code, errorBody("organization_failed", e.message)
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return 409, errorBody("organization_conflict", "Такое имя уже существует.")
	}
	if errors.As(err, &pg) && pg.Code == "23503" {
		return 409, errorBody("organization_conflict", "Письмо или метка изменены. Обновите список.")
	}
	return 500, errorBody("internal", "Не удалось изменить организацию почты.")
}
func (s *Server) organizationAccess(ctx context.Context, slug, box string) error {
	ws, _, err := s.scope(ctx, slug, workspace.RoleMember)
	if err != nil {
		return organizationError{404, "Ящик не найден."}
	}
	mailbox, err := s.inbound.MailboxByID(ctx, box)
	if err != nil || mailbox.WorkspaceID != ws {
		return organizationError{404, "Ящик не найден."}
	}
	user, _ := account.CurrentUser(ctx)
	ok, err := s.inbound.CanAccess(ctx, user.ID, box)
	if err != nil {
		return err
	}
	if !ok {
		return organizationError{404, "Ящик не найден."}
	}
	return nil
}
func (s *Server) GetMailOrganization(ctx context.Context, r GetMailOrganizationRequestObject) (GetMailOrganizationResponseObject, error) {
	if err := s.organizationAccess(ctx, r.Slug, r.MailboxId.String()); err != nil {
		code, body := organizationFailure(err)
		return GetMailOrganizationdefaultJSONResponse{StatusCode: code, Body: body}, nil
	}
	out := MailOrganization{Folders: []MailFolder{}, Labels: []MailLabel{}}
	rows, err := s.pool.Query(ctx, `SELECT f.name,f.uidvalidity,count(m.id),count(m.id) FILTER(WHERE m.read_at IS NULL) FROM imap_folders f LEFT JOIN messages m ON m.mailbox_id=f.mailbox_id AND m.folder=f.name WHERE f.mailbox_id=$1 GROUP BY f.name,f.uidvalidity ORDER BY f.name`, r.MailboxId)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var f MailFolder
		if err = rows.Scan(&f.Name, &f.Uidvalidity, &f.Total, &f.Unread); err != nil {
			rows.Close()
			return nil, err
		}
		f.System = inbound.IsSystemFolder(f.Name)
		out.Folders = append(out.Folders, f)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = s.pool.Query(ctx, `SELECT l.id,l.name,l.version,(SELECT count(*) FROM message_labels ml JOIN messages m ON m.id=ml.message_id
 WHERE ml.label_id=l.id AND m.read_at IS NULL AND m.folder NOT IN ('Junk','Trash'))::int
 FROM mail_labels l WHERE l.mailbox_id=$1 ORDER BY l.name,l.id`, r.MailboxId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var label MailLabel
		var unread int
		if err = rows.Scan(&label.Id, &label.Name, &label.Version, &unread); err != nil {
			return nil, err
		}
		label.Unread = &unread
		out.Labels = append(out.Labels, label)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return GetMailOrganization200JSONResponse(out), nil
}
func (s *Server) folderMutation(ctx context.Context, box, name string, old *string, validity *int64, remove bool) error {
	if !inbound.IsWebFolder(name) || inbound.IsSystemFolder(name) || strings.EqualFold(name, "INBOX") {
		return organizationError{400, "Выберите имя пользовательской папки до 200 байт, без / и управляющих символов."}
	}
	if old != nil && (!inbound.IsWebFolder(*old) || inbound.IsSystemFolder(*old) || validity == nil) {
		return organizationError{400, "Системные папки нельзя изменять; нужна версия папки."}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, box); err != nil {
		return err
	}
	if old == nil {
		var count int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM imap_folders WHERE mailbox_id=$1`, box).Scan(&count); err != nil {
			return err
		}
		if count >= 104 {
			return organizationError{400, "Достигнут лимит папок (104 вместе с системными)."}
		}
		_, err = tx.Exec(ctx, `INSERT INTO imap_folders(mailbox_id,name) VALUES($1,$2)`, box, name)
	} else {
		var found int64
		err = tx.QueryRow(ctx, `SELECT uidvalidity FROM imap_folders WHERE mailbox_id=$1 AND name=$2 FOR UPDATE`, box, *old).Scan(&found)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && found != *validity {
			return organizationError{409, "Папка изменена или удалена. Обновите список."}
		}
		if err != nil {
			return err
		}
		if remove {
			var count int
			if err = tx.QueryRow(ctx, `SELECT count(*) FROM messages WHERE mailbox_id=$1 AND folder=$2`, box, *old).Scan(&count); err != nil {
				return err
			}
			if count > 0 {
				return organizationError{409, "Папка не пуста. Сначала переместите письма."}
			}
			_, err = tx.Exec(ctx, `DELETE FROM imap_folders WHERE mailbox_id=$1 AND name=$2`, box, *old)
		} else {
			_, err = tx.Exec(ctx, `UPDATE imap_folders SET name=$3 WHERE mailbox_id=$1 AND name=$2`, box, *old, name)
		}
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *Server) SaveMailFolder(ctx context.Context, r SaveMailFolderRequestObject) (SaveMailFolderResponseObject, error) {
	err := s.organizationAccess(ctx, r.Slug, r.MailboxId.String())
	if err == nil {
		if r.Body == nil {
			err = organizationError{400, "Нужно имя папки."}
		} else {
			err = s.folderMutation(ctx, r.MailboxId.String(), r.Body.Name, r.Body.OldName, r.Body.Uidvalidity, false)
		}
	}
	if err != nil {
		code, body := organizationFailure(err)
		return SaveMailFolderdefaultJSONResponse{StatusCode: code, Body: body}, nil
	}
	return SaveMailFolder204Response{}, nil
}
func (s *Server) DeleteMailFolder(ctx context.Context, r DeleteMailFolderRequestObject) (DeleteMailFolderResponseObject, error) {
	err := s.organizationAccess(ctx, r.Slug, r.MailboxId.String())
	if err == nil {
		err = s.folderMutation(ctx, r.MailboxId.String(), r.Params.Name, &r.Params.Name, &r.Params.Uidvalidity, true)
	}
	if err != nil {
		code, body := organizationFailure(err)
		return DeleteMailFolderdefaultJSONResponse{StatusCode: code, Body: body}, nil
	}
	return DeleteMailFolder204Response{}, nil
}
func (s *Server) saveLabel(ctx context.Context, box, id, name string, version int) (MailLabel, error) {
	var result MailLabel
	if name == "" || name != strings.TrimSpace(name) || utf8.RuneCountInString(name) > 80 || strings.IndexFunc(name, unicode.IsControl) >= 0 || version < 0 {
		return result, organizationError{400, "Имя метки: от 1 до 80 символов; нужна версия."}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return result, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, box); err != nil {
		return result, err
	}
	var old MailLabel
	err = tx.QueryRow(ctx, `SELECT id,name,version FROM mail_labels WHERE mailbox_id=$1 AND id=$2 FOR UPDATE`, box, id).Scan(&old.Id, &old.Name, &old.Version)
	if err == nil {
		if old.Version == version+1 && old.Name == name {
			return old, nil
		}
		if old.Version != version {
			return result, organizationError{409, "Метка изменена. Обновите список."}
		}
		err = tx.QueryRow(ctx, `UPDATE mail_labels SET name=$3,version=version+1 WHERE mailbox_id=$1 AND id=$2 RETURNING id,name,version`, box, id, name).Scan(&result.Id, &result.Name, &result.Version)
	} else if errors.Is(err, pgx.ErrNoRows) {
		if version != 0 {
			return result, organizationError{409, "Метка удалена или недоступна."}
		}
		var count int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM mail_labels WHERE mailbox_id=$1`, box).Scan(&count); err != nil {
			return result, err
		}
		if count >= 100 {
			return result, organizationError{400, "Можно создать до 100 меток на ящик."}
		}
		err = tx.QueryRow(ctx, `INSERT INTO mail_labels(id,mailbox_id,name) VALUES($1,$2,$3) ON CONFLICT(id) DO NOTHING RETURNING id,name,version`, id, box, name).Scan(&result.Id, &result.Name, &result.Version)
		if errors.Is(err, pgx.ErrNoRows) {
			return result, organizationError{404, "Метка не найдена."}
		}
	}
	if err != nil {
		return result, err
	}
	if err = tx.Commit(ctx); err != nil {
		return result, err
	}
	return result, nil
}
func (s *Server) SaveMailLabel(ctx context.Context, r SaveMailLabelRequestObject) (SaveMailLabelResponseObject, error) {
	err := s.organizationAccess(ctx, r.Slug, r.MailboxId.String())
	var label MailLabel
	if err == nil {
		if r.Body == nil {
			err = organizationError{400, "Нужно имя метки."}
		} else {
			label, err = s.saveLabel(ctx, r.MailboxId.String(), r.LabelId.String(), r.Body.Name, r.Body.Version)
		}
	}
	if err != nil {
		code, body := organizationFailure(err)
		return SaveMailLabeldefaultJSONResponse{StatusCode: code, Body: body}, nil
	}
	return SaveMailLabel200JSONResponse(label), nil
}
func (s *Server) DeleteMailLabel(ctx context.Context, r DeleteMailLabelRequestObject) (DeleteMailLabelResponseObject, error) {
	err := s.organizationAccess(ctx, r.Slug, r.MailboxId.String())
	if err == nil {
		// The version predicate and row lock serialize deletion with renaming.
		var tag pgconn.CommandTag
		tag, err = s.pool.Exec(ctx, `DELETE FROM mail_labels WHERE mailbox_id=$1 AND id=$2 AND version=$3`, r.MailboxId, r.LabelId, r.Params.Version)
		if err == nil && tag.RowsAffected() == 0 {
			err = organizationError{409, "Метка изменена или удалена. Обновите список."}
		}
	}
	if err != nil {
		code, body := organizationFailure(err)
		return DeleteMailLabeldefaultJSONResponse{StatusCode: code, Body: body}, nil
	}
	return DeleteMailLabel204Response{}, nil
}
func (s *Server) labelMessage(ctx context.Context, slug, id string) (*inbound.Message, error) {
	ws, _, err := s.scope(ctx, slug, workspace.RoleMember)
	if err != nil {
		return nil, organizationError{404, "Письмо не найдено."}
	}
	msg, err := s.readableMessage(ctx, ws, id)
	if err != nil {
		return nil, organizationError{404, "Письмо не найдено."}
	}
	return msg, nil
}
func (s *Server) GetMessageLabels(ctx context.Context, r GetMessageLabelsRequestObject) (GetMessageLabelsResponseObject, error) {
	msg, err := s.labelMessage(ctx, r.Slug, r.MessageId.String())
	if err != nil {
		code, body := organizationFailure(err)
		return GetMessageLabelsdefaultJSONResponse{StatusCode: code, Body: body}, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT l.id,l.name,l.version FROM mail_labels l JOIN message_labels ml ON ml.label_id=l.id WHERE ml.message_id=$1 AND ml.mailbox_id=$2 ORDER BY l.name,l.id`, msg.ID, msg.MailboxID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := MessageLabels{Labels: []MailLabel{}}
	for rows.Next() {
		var label MailLabel
		if err = rows.Scan(&label.Id, &label.Name, &label.Version); err != nil {
			return nil, err
		}
		out.Labels = append(out.Labels, label)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return GetMessageLabels200JSONResponse(out), nil
}
func (s *Server) ChangeMessageLabel(ctx context.Context, r ChangeMessageLabelRequestObject) (ChangeMessageLabelResponseObject, error) {
	msg, err := s.labelMessage(ctx, r.Slug, r.MessageId.String())
	if err == nil {
		if r.Body == nil {
			err = organizationError{400, "Нужна метка."}
		} else {
			var tag pgconn.CommandTag
			if r.Body.Applied {
				tag, err = s.pool.Exec(ctx, `INSERT INTO message_labels(mailbox_id,message_id,label_id) SELECT $1,$2,id FROM mail_labels WHERE mailbox_id=$1 AND id=$3 ON CONFLICT(message_id,label_id) DO UPDATE SET label_id=EXCLUDED.label_id`, msg.MailboxID, msg.ID, r.Body.Id)
				if err == nil && tag.RowsAffected() == 0 {
					err = organizationError{404, "Метка не найдена в этом ящике."}
				}
			} else {
				_, err = s.pool.Exec(ctx, `DELETE FROM message_labels WHERE mailbox_id=$1 AND message_id=$2 AND label_id=$3`, msg.MailboxID, msg.ID, r.Body.Id)
			}
		}
	}
	if err != nil {
		code, body := organizationFailure(err)
		return ChangeMessageLabeldefaultJSONResponse{StatusCode: code, Body: body}, nil
	}
	return ChangeMessageLabel204Response{}, nil
}
