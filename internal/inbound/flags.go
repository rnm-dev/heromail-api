package inbound

import (
	"context"
	"strings"
)

// One row UPDATE merges only supplied flags, preserving concurrent IMAP flags.
func (s *Store) UpdateFlags(ctx context.Context, box, id string, read, starred *bool) (*Message, error) {
	return scanMessage(s.pool.QueryRow(ctx, `UPDATE messages SET
 read_at=CASE WHEN $3::boolean IS NULL THEN read_at WHEN $3 THEN coalesce(read_at,now()) ELSE NULL END,
 imap_flags=CASE WHEN $4::boolean IS NULL THEN imap_flags WHEN $4 THEN array_append(array_remove(imap_flags,'\Flagged'),'\Flagged') ELSE array_remove(imap_flags,'\Flagged') END
 WHERE mailbox_id=$1 AND id=$2 RETURNING `+strings.ReplaceAll(messageColumns, "msg.", ""), box, id, read, starred))
}

// UnreadCounts covers every mailbox the user can read, or only box when given.
func (s *Store) UnreadCounts(ctx context.Context, userID string, box *string) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, `SELECT msg.folder,count(*),count(*) FILTER (WHERE '\Flagged'=ANY(msg.imap_flags)),
 count(*) FILTER (WHERE msg.category='people'),count(*) FILTER (WHERE msg.category='notifications'),count(*) FILTER (WHERE msg.category='newsletters')
 FROM messages msg JOIN mailboxes m ON m.id=msg.mailbox_id JOIN domains d ON d.id=m.domain_id
 JOIN workspaces w ON w.id=coalesce(m.personal_workspace_id,d.workspace_id)
 JOIN workspace_members wm ON wm.workspace_id=w.id AND wm.user_id=$1
 WHERE msg.read_at IS NULL AND ((coalesce(m.owner_user_id,w.personal_owner_id) IS NULL AND NOT EXISTS(SELECT 1 FROM mailbox_members mx WHERE mx.mailbox_id=m.id)) OR coalesce(m.owner_user_id,w.personal_owner_id)=$1 OR EXISTS(SELECT 1 FROM mailbox_members mm WHERE mm.mailbox_id=m.id AND mm.user_id=$1))
 AND ($2::uuid IS NULL OR m.id=$2)
 GROUP BY msg.folder`, userID, box)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	// INBOX:<category> keys feed the Inbox tabs; INBOX stays the folder total.
	out := map[string]int{"INBOX": 0, "Junk": 0, "Archive": 0, "Trash": 0, "starred": 0,
		"INBOX:people": 0, "INBOX:notifications": 0, "INBOX:newsletters": 0}
	for rows.Next() {
		var folder string
		var count, starred, people, notifications, newsletters int
		if err := rows.Scan(&folder, &count, &starred, &people, &notifications, &newsletters); err != nil {
			return nil, err
		}
		out[folder] = count
		out["starred"] += starred
		if folder == "INBOX" {
			out["INBOX:people"], out["INBOX:notifications"], out["INBOX:newsletters"] = people, notifications, newsletters
		}
	}
	return out, rows.Err()
}
