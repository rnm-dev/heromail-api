package inbound

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const uniqueViolation = "23505"

type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// Corporate mailboxes inherit their domain tenant. Personal addresses override
// it with their private workspace; every mailbox/message read uses that scope.
const mailboxColumns = ` m.id, m.domain_id, coalesce(m.personal_workspace_id, d.workspace_id),
	m.local_part || '@' || d.domain AS address, m.name, m.created_at, m.updated_at, m.owner_user_id, EXISTS(SELECT 1 FROM mailbox_smtp_credentials c WHERE c.mailbox_id=m.id)`

func scanMailbox(row pgx.Row) (*Mailbox, error) {
	var m Mailbox
	err := row.Scan(&m.ID, &m.DomainID, &m.WorkspaceID, &m.Address, &m.Name, &m.CreatedAt, &m.UpdatedAt, &m.OwnerUserID, &m.SMTPPasswordSet)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoMailbox
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// MailboxByAddress resolves a full address to the mailbox that accepts it.
//
// The domain must be **verified**: accepting mail for a domain whose ownership
// was never proven would let anyone who typed a name into our UI intercept
// somebody else's mail by pointing its MX here.
func (s *Store) MailboxByAddress(ctx context.Context, address string) (*Mailbox, error) {
	local, domain, ok := splitAddr(address)
	if !ok {
		return nil, ErrNoMailbox
	}
	return scanMailbox(s.pool.QueryRow(ctx, `
		SELECT`+mailboxColumns+`
		FROM mailboxes m JOIN domains d ON d.id = m.domain_id
		WHERE m.local_part = $1 AND d.domain = $2 AND d.verified_at IS NOT NULL`,
		local, domain))
}

// CreateMailbox adds an address under a domain the caller already owns.
func (s *Store) CreateMailbox(ctx context.Context, domainID, localPart, name string, owner ...*string) (*Mailbox, error) {
	var id string
	var ownerID *string
	if len(owner) > 0 {
		ownerID = owner[0]
	}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO mailboxes (domain_id, local_part, name, owner_user_id)
		VALUES ($1, $2, nullif($3, ''), $4) RETURNING id`,
		domainID, strings.ToLower(strings.TrimSpace(localPart)), strings.TrimSpace(name), ownerID).Scan(&id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return nil, fmt.Errorf("address already exists")
		}
		return nil, fmt.Errorf("insert mailbox: %w", err)
	}
	return s.MailboxByID(ctx, id)
}

func (s *Store) MailboxByID(ctx context.Context, id string) (*Mailbox, error) {
	return scanMailbox(s.pool.QueryRow(ctx, `
		SELECT`+mailboxColumns+`
		FROM mailboxes m JOIN domains d ON d.id = m.domain_id WHERE m.id = $1`, id))
}

// MailboxesForWorkspace lists every address the workspace can read.
func (s *Store) MailboxesForWorkspace(ctx context.Context, workspaceID string) ([]Mailbox, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT`+mailboxColumns+`
		FROM mailboxes m JOIN domains d ON d.id = m.domain_id
		WHERE coalesce(m.personal_workspace_id, d.workspace_id) = $1 ORDER BY address`, workspaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Mailbox, 0)
	for rows.Next() {
		m, err := scanMailbox(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *m)
	}
	return out, rows.Err()
}

// Every column is qualified because two of these queries join mailboxes and
// domains, where a bare `id` is ambiguous. Qualifying all of them keeps one
// column list usable everywhere instead of two that can drift apart.
const messageColumns = ` msg.id, msg.mailbox_id, msg.envelope_from, msg.envelope_to, msg.message_id,
	msg.from_addr, msg.from_name, msg.subject, msg.sent_at, msg.text_body, msg.html_body,
	msg.size_bytes, msg.spf_pass, msg.dkim_pass, msg.read_at, msg.received_at, msg.folder`

func scanMessage(row pgx.Row) (*Message, error) {
	var m Message
	err := row.Scan(&m.ID, &m.MailboxID, &m.EnvelopeFrom, &m.EnvelopeTo, &m.MessageID,
		&m.FromAddr, &m.FromName, &m.Subject, &m.SentAt, &m.TextBody, &m.HTMLBody,
		&m.SizeBytes, &m.SPFPass, &m.DKIMPass, &m.ReadAt, &m.ReceivedAt, &m.Folder)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoMailbox
	}
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// DeliverParams is one message being handed to us by the MTA.
type DeliverParams struct {
	MailboxID    string
	EnvelopeFrom string
	EnvelopeTo   string
	Raw          []byte
}

// Deliver stores a received message.
//
// A repeat of a message we already hold returns ErrDuplicate rather than a
// second row: a sending server that timed out mid-handoff will retry, and the
// Message-ID is what identifies the retry as the same mail.
func (s *Store) Deliver(ctx context.Context, p DeliverParams) (*Message, error) {
	f := parse(p.Raw)
	folder := deliveryFolder(p.Raw)
	if _, err := s.pool.Exec(ctx, `INSERT INTO imap_folders(mailbox_id,name) VALUES($1,$2) ON CONFLICT DO NOTHING`, p.MailboxID, folder); err != nil {
		return nil, err
	}

	m, err := scanMessage(s.pool.QueryRow(ctx, `
		INSERT INTO messages (mailbox_id, envelope_from, envelope_to, message_id,
			from_addr, from_name, subject, sent_at, text_body, html_body, raw, size_bytes, folder)
		VALUES ($1, $2, $3, nullif($4, ''), nullif($5, ''), nullif($6, ''), $7, $8,
			nullif($9, ''), nullif($10, ''), $11, $12, $13)
		RETURNING`+strings.ReplaceAll(messageColumns, "msg.", ""),
		p.MailboxID, p.EnvelopeFrom, p.EnvelopeTo, f.MessageID,
		f.FromAddr, f.FromName, f.Subject, f.SentAt, f.Text, f.HTML,
		p.Raw, len(p.Raw), folder))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return nil, ErrDuplicate
		}
		return nil, fmt.Errorf("insert message: %w", err)
	}
	return m, nil
}

// ListMessages returns a mailbox's messages, newest first.
func (s *Store) ListMessages(ctx context.Context, mailboxID string, limit int, offset ...int) ([]Message, error) {
	skip := 0
	if len(offset) > 0 {
		skip = offset[0]
	}
	return s.ListFolderMessages(ctx, mailboxID, "INBOX", limit, skip)
}

// SearchFolderMessages filters a folder by a free-text query.
//
// strpos rather than ILIKE because ILIKE treats %, _ and backslash as
// wildcards: a search for "50%" would otherwise match far more than it should,
// and escaping user input into a pattern is the kind of thing that is wrong
// once and then wrong forever.
//
// Subject, sender and body are searched together — someone looking for a
// message remembers whichever of those stuck, and asking them which field it
// was is a worse product than one query over all three.
func (s *Store) SearchFolderMessages(ctx context.Context, mailboxID, folder, query string, limit, skip int) ([]Message, error) {
	rows, err := s.pool.Query(ctx, `
 SELECT`+messageColumns+`
 FROM messages msg
 WHERE msg.mailbox_id=$1 AND msg.folder=$4
   AND strpos(lower(concat_ws(' ', msg.subject, msg.from_addr, msg.from_name, msg.text_body)), lower($5)) > 0
 ORDER BY msg.received_at DESC, msg.id DESC LIMIT $2 OFFSET $3`,
		mailboxID, limit, skip, folder, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Message, 0)
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *m)
	}
	return out, rows.Err()
}

func (s *Store) ListFolderMessages(ctx context.Context, mailboxID, folder string, limit, skip int) ([]Message, error) {
	rows, err := s.pool.Query(ctx, `
 SELECT`+messageColumns+`
 FROM messages msg WHERE msg.mailbox_id=$1 AND msg.folder=$4 ORDER BY msg.received_at DESC,msg.id DESC LIMIT $2 OFFSET $3`, mailboxID, limit, skip, folder)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]Message, 0)
	for rows.Next() {
		m, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *m)
	}
	return out, rows.Err()
}

// MessageByID reads one message, scoped to the workspace that owns its
// mailbox. Another tenant's message reads as absent, the same way emails and
// domains behave.
func (s *Store) MessageByID(ctx context.Context, workspaceID, id string) (*Message, error) {
	return scanMessage(s.pool.QueryRow(ctx, `
		SELECT`+messageColumns+`
		FROM messages msg
		JOIN mailboxes mb ON mb.id = msg.mailbox_id
		JOIN domains d ON d.id = mb.domain_id
		WHERE msg.id = $1 AND coalesce(mb.personal_workspace_id, d.workspace_id) = $2`, id, workspaceID))
}

// MarkRead stamps read_at, scoped the same way.
func (s *Store) MarkRead(ctx context.Context, workspaceID, id string) (*Message, error) {
	return scanMessage(s.pool.QueryRow(ctx, `
		UPDATE messages SET read_at = coalesce(read_at, now())
		WHERE id = $1 AND mailbox_id IN (
			SELECT mb.id FROM mailboxes mb JOIN domains d ON d.id = mb.domain_id
			WHERE coalesce(mb.personal_workspace_id, d.workspace_id) = $2)
		RETURNING`+strings.ReplaceAll(messageColumns, "msg.", ""), id, workspaceID))
}

func splitAddr(address string) (local, domain string, ok bool) {
	address = strings.ToLower(strings.TrimSpace(address))
	at := strings.LastIndex(address, "@")
	if at <= 0 || at+1 >= len(address) {
		return "", "", false
	}
	return address[:at], address[at+1:], true
}
