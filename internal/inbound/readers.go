package inbound

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// MailboxReaders lists the users who may read a mailbox — the inverse of
// AccessibleMailboxes, under the same rules — and the workspace slug the
// mailbox is reached under. Push notifications go to exactly these people.
func (s *Store) MailboxReaders(ctx context.Context, mailboxID string) (slug string, users []string, err error) {
	rows, err := s.pool.Query(ctx, `SELECT w.slug, wm.user_id::text FROM mailboxes m JOIN domains d ON d.id=m.domain_id
 JOIN workspaces w ON w.id=coalesce(m.personal_workspace_id,d.workspace_id)
 JOIN workspace_members wm ON wm.workspace_id=w.id
 WHERE m.id=$1 AND ((coalesce(m.owner_user_id,w.personal_owner_id) IS NULL AND NOT EXISTS(SELECT 1 FROM mailbox_members mx WHERE mx.mailbox_id=m.id)) OR coalesce(m.owner_user_id,w.personal_owner_id)=wm.user_id OR EXISTS(SELECT 1 FROM mailbox_members mm WHERE mm.mailbox_id=m.id AND mm.user_id=wm.user_id))
 ORDER BY wm.user_id`, mailboxID)
	if err != nil {
		return "", nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var user string
		if err := rows.Scan(&slug, &user); err != nil {
			return "", nil, err
		}
		users = append(users, user)
	}
	return slug, users, rows.Err()
}

// MessageForPush loads a message by id alone, for background work that has no
// workspace scope to check against. ErrNoMailbox when it is gone.
func (s *Store) MessageForPush(ctx context.Context, id string) (*Message, error) {
	m, err := scanMessage(s.pool.QueryRow(ctx, `SELECT`+messageColumns+` FROM messages msg WHERE msg.id=$1`, id))
	if err == pgx.ErrNoRows {
		return nil, ErrNoMailbox
	}
	return m, err
}
