package httpapi

import (
	"context"
	"errors"
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/rnm/heromail/backend/internal/account"
)

func scanContact(row pgx.Row) (Contact, error) {
	var c Contact
	err := row.Scan(&c.Id, &c.Name, &c.Email, &c.Version)
	return c, err
}
func (s *Server) ListContacts(ctx context.Context, r ListContactsRequestObject) (ListContactsResponseObject, error) {
	user, _ := account.CurrentUser(ctx)
	q := ""
	if r.Params.Q != nil {
		q = strings.TrimSpace(*r.Params.Q)
	}
	offset := 0
	if r.Params.Offset != nil {
		offset = *r.Params.Offset
	}
	if offset < 0 || utf8.RuneCountInString(q) > 200 {
		return ListContacts400JSONResponse{BadRequestJSONResponse(errorBody("validation_failed", "invalid search or offset"))}, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT id,name,email,version FROM contacts WHERE user_id=$1 AND strpos(lower(name||' '||email),lower($2))>0 ORDER BY lower(name),email,id LIMIT 51 OFFSET $3`, user.ID, q, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Contact{}
	for rows.Next() {
		c, err := scanContact(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	more := len(result) > 50
	if more {
		result = result[:50]
	}
	return ListContacts200JSONResponse{Contacts: result, HasMore: more}, nil
}
func (s *Server) SaveContact(ctx context.Context, r SaveContactRequestObject) (SaveContactResponseObject, error) {
	if r.Body == nil {
		return SaveContact400JSONResponse{BadRequestJSONResponse(errorBody("validation_failed", "contact required"))}, nil
	}
	name := strings.TrimSpace(r.Body.Name)
	address := strings.ToLower(strings.TrimSpace(string(r.Body.Email)))
	parsed, err := mail.ParseAddress(address)
	if err != nil || parsed.Address != address || strings.IndexFunc(address, unicode.IsControl) >= 0 || len(address) > 254 || utf8.RuneCountInString(name) > 200 || strings.IndexFunc(name, unicode.IsControl) >= 0 || r.Body.Version < 0 {
		return SaveContact400JSONResponse{BadRequestJSONResponse(errorBody("validation_failed", "Укажите один email без имени; имя до 200 символов."))}, nil
	}
	user, _ := account.CurrentUser(ctx)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	// Serialize the per-user limit and optimistic writes without touching other accounts.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,2))`, user.ID); err != nil {
		return nil, err
	}
	old, err := scanContact(tx.QueryRow(ctx, `SELECT id,name,email,version FROM contacts WHERE id=$1 AND user_id=$2 FOR UPDATE`, r.Id, user.ID))
	exists := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if exists && old.Version == r.Body.Version+1 && old.Name == name && string(old.Email) == address {
		return SaveContact200JSONResponse(old), nil
	}
	if (exists && old.Version != r.Body.Version) || (!exists && r.Body.Version != 0) {
		return SaveContact409JSONResponse(errorBody("contact_conflict", "Контакт изменён или удалён на другом устройстве. Обновите список.")), nil
	}
	var c Contact
	if !exists {
		var count int
		if err = tx.QueryRow(ctx, `SELECT count(*) FROM contacts WHERE user_id=$1`, user.ID).Scan(&count); err != nil {
			return nil, err
		}
		if count >= 2000 {
			return SaveContact400JSONResponse{BadRequestJSONResponse(errorBody("contact_limit", "В адресной книге можно сохранить до 2000 контактов."))}, nil
		}
		c, err = scanContact(tx.QueryRow(ctx, `INSERT INTO contacts(id,user_id,name,email) VALUES($1,$2,$3,$4) ON CONFLICT(id) DO NOTHING RETURNING id,name,email,version`, r.Id, user.ID, name, address))
	} else {
		c, err = scanContact(tx.QueryRow(ctx, `UPDATE contacts SET name=$3,email=$4,version=version+1 WHERE id=$1 AND user_id=$2 RETURNING id,name,email,version`, r.Id, user.ID, name, address))
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return SaveContact404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "contact not found"))}, nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return SaveContact409JSONResponse(errorBody("contact_exists", "Этот email уже есть в вашей адресной книге.")), nil
	}
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return SaveContact200JSONResponse(c), nil
}
func (s *Server) DeleteContact(ctx context.Context, r DeleteContactRequestObject) (DeleteContactResponseObject, error) {
	user, _ := account.CurrentUser(ctx)
	if r.Params.Version < 1 {
		return DeleteContact400JSONResponse{BadRequestJSONResponse(errorBody("validation_failed", "version required"))}, nil
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM contacts WHERE id=$1 AND user_id=$2 AND version=$3`, r.Id, user.ID, r.Params.Version)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if err = s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM contacts WHERE id=$1 AND user_id=$2)`, r.Id, user.ID).Scan(&exists); err != nil {
			return nil, err
		}
		if exists {
			return DeleteContact409JSONResponse(errorBody("contact_conflict", "Контакт изменён. Обновите список перед удалением.")), nil
		}
		return DeleteContact404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "contact not found"))}, nil
	}
	return DeleteContact204Response{}, nil
}
