package email

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when no email matches within the workspace. Rows
// belonging to another tenant are indistinguishable from rows that do not
// exist, which is what keeps ids from leaking across workspaces.
var ErrNotFound = errors.New("email not found")

// ErrDuplicateIdempotencyKey signals that a concurrent request already created
// the row. Callers re-read instead of failing.
var ErrDuplicateIdempotencyKey = errors.New("duplicate idempotency key")

// uniqueViolation is the SQLSTATE Postgres raises for a unique index conflict.
const uniqueViolation = "23505"

// Store is the only thing in this package that talks to Postgres.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// selectColumns keeps the column list and the scan order in one place.
const selectColumns = `
	id, workspace_id, from_addr, to_addrs, subject, html_body, text_body,
	status, provider_message_id, idempotency_key, attempts, last_error,
	created_at, updated_at, cc_addrs, bcc_addrs`

func scanEmail(row pgx.Row) (*Email, error) {
	var e Email
	err := row.Scan(
		&e.ID, &e.WorkspaceID, &e.FromAddr, &e.ToAddrs, &e.Subject,
		&e.HTMLBody, &e.TextBody, &e.Status, &e.ProviderMessageID,
		&e.IdempotencyKey, &e.Attempts, &e.LastError, &e.CreatedAt, &e.UpdatedAt, &e.CcAddrs, &e.BccAddrs,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// CreateParams is the data needed to record a new outbound message.
type CreateParams struct {
	WorkspaceID    string
	FromAddr       string
	ToAddrs        []string
	CcAddrs        []string
	BccAddrs       []string
	Subject        string
	HTMLBody       string
	TextBody       string
	IdempotencyKey string
}

// Create inserts the email as queued together with its first event, in one
// transaction: an email that exists without a trail would be a hole in the log.
func (s *Store) Create(ctx context.Context, p CreateParams) (*Email, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	email, err := scanEmail(tx.QueryRow(ctx, `
		INSERT INTO emails (workspace_id, from_addr, to_addrs, subject, html_body, text_body, idempotency_key, cc_addrs, bcc_addrs)
		VALUES ($1, $2, $3, $4, nullif($5, ''), nullif($6, ''), nullif($7, ''), coalesce($8::text[], '{}'), coalesce($9::text[], '{}'))
		RETURNING`+selectColumns,
		p.WorkspaceID, p.FromAddr, p.ToAddrs, p.Subject, p.HTMLBody, p.TextBody, p.IdempotencyKey, p.CcAddrs, p.BccAddrs,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return nil, ErrDuplicateIdempotencyKey
		}
		return nil, fmt.Errorf("insert email: %w", err)
	}

	if err := insertEvent(ctx, tx, email.ID, EventQueued, nil); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return email, nil
}

// MarkProcessing records that a worker has picked the message up. The guard on
// the current status makes this the claim: a message already sent or dead is
// not re-sent if a duplicate task shows up.
func (s *Store) MarkProcessing(ctx context.Context, id string) (*Email, error) {
	return s.finish(ctx, EventProcessing,
		`UPDATE emails SET status = 'processing'
		 WHERE id = $1 AND status IN ('queued', 'failed')
		 RETURNING`+selectColumns,
		[]any{id},
		nil,
	)
}

// MarkDead records that retries are exhausted. Terminal: no worker will pick
// it up again.
func (s *Store) MarkDead(ctx context.Context, id, reason string) (*Email, error) {
	return s.finish(ctx, EventFailed,
		`UPDATE emails
		 SET status = 'dead', attempts = attempts + 1, last_error = $2
		 WHERE id = $1
		 RETURNING`+selectColumns,
		[]any{id, reason},
		map[string]string{"error": reason, "final": "true"},
	)
}

// MarkSent records a successful hand-off to the provider.
func (s *Store) MarkSent(ctx context.Context, id, providerMessageID string) (*Email, error) {
	return s.finish(ctx, EventSent,
		`UPDATE emails
		 SET status = 'sent', provider_message_id = $2, attempts = attempts + 1, last_error = NULL
		 WHERE id = $1
		 RETURNING`+selectColumns,
		[]any{id, providerMessageID},
		map[string]string{"provider_message_id": providerMessageID},
	)
}

// MarkFailed records a failed attempt and why.
func (s *Store) MarkFailed(ctx context.Context, id, reason string) (*Email, error) {
	return s.finish(ctx, EventFailed,
		`UPDATE emails
		 SET status = 'failed', attempts = attempts + 1, last_error = $2
		 WHERE id = $1
		 RETURNING`+selectColumns,
		[]any{id, reason},
		map[string]string{"error": reason},
	)
}

// finish applies a status update and its event atomically, so the status and
// the event trail can never disagree.
func (s *Store) finish(
	ctx context.Context, eventType EventType,
	query string, args []any, detail map[string]string,
) (*Email, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	email, err := scanEmail(tx.QueryRow(ctx, query, args...))
	if err != nil {
		return nil, err
	}

	// A nil detail stays SQL NULL rather than the JSON string "null", so an
	// event with nothing to say reads as empty instead of as a value.
	var payload []byte
	if detail != nil {
		payload, err = json.Marshal(detail)
		if err != nil {
			return nil, err
		}
	}
	if err := insertEvent(ctx, tx, email.ID, eventType, payload); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return email, nil
}

func insertEvent(ctx context.Context, tx pgx.Tx, emailID string, t EventType, detail []byte) error {
	_, err := tx.Exec(ctx,
		`INSERT INTO email_events (email_id, type, detail) VALUES ($1, $2, $3)`,
		emailID, t, detail)
	if err != nil {
		return fmt.Errorf("insert %s event: %w", t, err)
	}
	return nil
}

// ByID loads an email, scoped to the workspace.
func (s *Store) ByID(ctx context.Context, workspaceID, id string) (*Email, error) {
	return scanEmail(s.pool.QueryRow(ctx,
		`SELECT`+selectColumns+`
		 FROM emails WHERE id = $1 AND workspace_id = $2`, id, workspaceID))
}

// ByIDUnscoped loads an email without a workspace filter. Only the worker uses
// it: it acts on a task it was handed, not on a request from a tenant, so
// there is no caller whose scope it could check against.
func (s *Store) ByIDUnscoped(ctx context.Context, id string) (*Email, error) {
	return scanEmail(s.pool.QueryRow(ctx,
		`SELECT`+selectColumns+` FROM emails WHERE id = $1`, id))
}

// ByIdempotencyKey loads the email a previous request created under this key.
func (s *Store) ByIdempotencyKey(ctx context.Context, workspaceID, key string) (*Email, error) {
	return scanEmail(s.pool.QueryRow(ctx,
		`SELECT`+selectColumns+`
		 FROM emails WHERE workspace_id = $1 AND idempotency_key = $2`, workspaceID, key))
}

// SearchForUser searches outbound mail in every workspace the user belongs to.
// strpos treats %, _ and backslashes as ordinary characters, unlike ILIKE.
func (s *Store) SearchForUser(ctx context.Context, userID, query string, limit int) ([]Email, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT`+selectColumns+`
		FROM emails e
		WHERE EXISTS (
			SELECT 1 FROM workspace_members wm
			WHERE wm.workspace_id = e.workspace_id AND wm.user_id = $1
		)
		AND (e.retained_owner_id IS NULL OR e.retained_owner_id=$1)
		AND NOT EXISTS (SELECT 1 FROM mailboxes mb JOIN domains d ON d.id=mb.domain_id
            WHERE lower(mb.local_part || '@' || d.domain)=lower(e.from_addr) AND mb.owner_user_id IS NOT NULL AND mb.owner_user_id<>$1)
        AND strpos(lower(concat_ws(' ', e.from_addr, array_to_string(e.to_addrs, ' '),
			e.subject, e.text_body, e.html_body)), lower($2)) > 0
		ORDER BY e.created_at DESC
		LIMIT $3`, userID, query, limit)
	if err != nil {
		return nil, fmt.Errorf("search emails: %w", err)
	}
	defer rows.Close()

	result := make([]Email, 0)
	for rows.Next() {
		email, err := scanEmail(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *email)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("search emails: %w", err)
	}
	return result, nil
}

// ------------------------------------------------------------- attachments

// ErrAttachmentNotFound means an id does not exist, belongs to another
// workspace, or is already attached to a different message.
var ErrAttachmentNotFound = errors.New("attachment not found")

const attachmentColumns = ` id, workspace_id, email_id, filename, content_type, size_bytes, checksum_sha256, storage_key, created_at`

func scanAttachment(row pgx.Row) (*Attachment, error) {
	var a Attachment
	err := row.Scan(&a.ID, &a.WorkspaceID, &a.EmailID, &a.Filename, &a.ContentType,
		&a.SizeBytes, &a.ChecksumSHA, &a.StorageKey, &a.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAttachmentNotFound
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// InsertAttachmentParams is the data needed to record a stored upload.
type InsertAttachmentParams struct {
	WorkspaceID string
	Filename    string
	ContentType string
	SizeBytes   int64
	ChecksumSHA []byte
	StorageKey  string
}

// InsertAttachment records an upload as unattached (email_id NULL). It is
// attached to a message later, by AttachToEmail.
func (s *Store) InsertAttachment(ctx context.Context, p InsertAttachmentParams) (*Attachment, error) {
	return scanAttachment(s.pool.QueryRow(ctx, `
		INSERT INTO attachments (workspace_id, filename, content_type, size_bytes, checksum_sha256, storage_key)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING`+attachmentColumns,
		p.WorkspaceID, p.Filename, p.ContentType, p.SizeBytes, p.ChecksumSHA, p.StorageKey,
	))
}

// DeleteAttachment removes the row. Used to roll back an upload whose bytes
// never made it to the bucket, or that failed validation after being stored.
func (s *Store) DeleteAttachment(ctx context.Context, workspaceID, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM attachments WHERE id = $1 AND workspace_id = $2`, id, workspaceID)
	return err
}

// AttachmentsByIDs loads unattached attachments belonging to the workspace,
// for validating a send request before it commits to anything. Returns fewer
// rows than requested ids when one is missing, belongs to someone else, or is
// already attached — the caller is expected to notice the count mismatch.
func (s *Store) AttachmentsByIDs(ctx context.Context, workspaceID string, ids []string) ([]Attachment, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT`+attachmentColumns+`
		 FROM attachments WHERE workspace_id = $1 AND id = ANY($2) AND email_id IS NULL`,
		workspaceID, ids)
	if err != nil {
		return nil, fmt.Errorf("load attachments: %w", err)
	}
	defer rows.Close()

	var out []Attachment
	for rows.Next() {
		a, err := scanAttachment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// AttachToEmail claims a set of unattached, workspace-owned uploads for one
// message. The WHERE clause is also the guard against attaching someone
// else's file or reusing an id twice: rows affected less than len(ids) means
// one of those was true, and the caller must fail the request.
func (s *Store) AttachToEmail(ctx context.Context, workspaceID, emailID string, ids []string) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`UPDATE attachments SET email_id = $1
		 WHERE workspace_id = $2 AND id = ANY($3) AND email_id IS NULL`,
		emailID, workspaceID, ids)
	if err != nil {
		return 0, fmt.Errorf("attach: %w", err)
	}
	return tag.RowsAffected(), nil
}

// AttachmentsByEmailID lists what is attached to one message, in upload order.
func (s *Store) AttachmentsByEmailID(ctx context.Context, emailID string) ([]Attachment, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT`+attachmentColumns+` FROM attachments WHERE email_id = $1 ORDER BY created_at`, emailID)
	if err != nil {
		return nil, fmt.Errorf("load attachments: %w", err)
	}
	defer rows.Close()

	out := make([]Attachment, 0)
	for rows.Next() {
		a, err := scanAttachment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// Events returns the trail for an email, oldest first.
func (s *Store) Events(ctx context.Context, emailID string) ([]Event, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, email_id, type, detail, created_at
		 FROM email_events WHERE email_id = $1 ORDER BY created_at`, emailID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.EmailID, &e.Type, &e.Detail, &e.CreatedAt); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, rows.Err()
}
