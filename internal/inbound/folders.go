package inbound

import (
	"bytes"
	"context"
	"net/mail"
	"strings"
)

// Only Postfix may supply this header: cleanup strips incoming copies before
// Rspamd adds its verdict. LMTP is loopback-only. Subject and public spam headers
// are deliberately ignored; IMAP APPEND keeps the client's chosen folder.
func deliveryFolder(raw []byte) string {
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return "INBOX"
	}
	values := m.Header["X-Heromail-Spam"]
	if len(values) == 1 && strings.EqualFold(strings.TrimSpace(strings.SplitN(values[0], ",", 2)[0]), "Yes") {
		return "Junk"
	}
	return "INBOX"
}

func (s *Store) MoveMessage(ctx context.Context, box, id, folder string) (*Message, error) {
	if folder != "INBOX" && folder != "Junk" {
		return nil, ErrNoMailbox
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text,0))`, box); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO imap_folders(mailbox_id,name) VALUES($1,$2) ON CONFLICT DO NOTHING`, box, folder); err != nil {
		return nil, err
	}
	m, err := scanMessage(tx.QueryRow(ctx, `UPDATE messages SET imap_uid=CASE WHEN folder<>$3 THEN nextval('imap_uid_seq') ELSE imap_uid END,folder=$3 WHERE mailbox_id=$1 AND id=$2 RETURNING `+strings.ReplaceAll(messageColumns, "msg.", ""), box, id, folder))
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return m, nil
}
