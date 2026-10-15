package inbound

import (
	"bytes"
	"context"
	"net/mail"
	"strings"
	"time"
)

type SearchFilter struct {
	Query, From, To, Box, Folder string
	After, Before                *time.Time // inclusive start, exclusive end
	Attachments, Unread, Starred bool
	Limit, Offset                int
}
type SearchMatch struct {
	Message   Message
	Workspace string
}

// Cheap predicates and access checks run in SQL. MIME-only predicates run before
// pagination, streaming original bytes only when requested. A future metadata
// index can replace this scan without changing the API or its matching rules.
func (s *Store) SearchReceived(ctx context.Context, user string, f SearchFilter) ([]SearchMatch, bool, error) {
	needsMIME := f.To != "" || f.Attachments
	var sqlLimit *int
	sqlOffset := 0
	if !needsMIME {
		n := f.Limit + 1
		sqlLimit = &n
		sqlOffset = f.Offset
	}
	rows, err := s.pool.Query(ctx, `SELECT `+messageColumns+`,w.slug,CASE WHEN $9 THEN msg.raw ELSE NULL END
 FROM messages msg JOIN mailboxes m ON m.id=msg.mailbox_id JOIN domains d ON d.id=m.domain_id
 JOIN workspaces w ON w.id=coalesce(m.personal_workspace_id,d.workspace_id)
 JOIN workspace_members wm ON wm.workspace_id=w.id AND wm.user_id=$1
 WHERE (coalesce(m.owner_user_id,w.personal_owner_id) IS NULL OR coalesce(m.owner_user_id,w.personal_owner_id)=$1)
 AND ($2='' OR m.id::text=$2) AND ($3='All' OR msg.folder=$3)
 AND ($4='' OR strpos(lower(concat_ws(' ',msg.subject,msg.from_addr,msg.from_name,msg.envelope_from,msg.text_body)),lower($4))>0)
 AND ($5='' OR strpos(lower(concat_ws(' ',msg.from_addr,msg.from_name,msg.envelope_from)),lower($5))>0)
 AND ($6::timestamptz IS NULL OR msg.received_at >= $6) AND ($7::timestamptz IS NULL OR msg.received_at < $7)
 AND (NOT $8 OR msg.read_at IS NULL) AND (NOT $10 OR '\Flagged'=ANY(msg.imap_flags))
 ORDER BY msg.received_at DESC,msg.id DESC LIMIT $11 OFFSET $12`, user, f.Box, f.Folder, f.Query, f.From, f.After, f.Before, f.Unread, needsMIME, f.Starred, sqlLimit, sqlOffset)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := make([]SearchMatch, 0, f.Limit)
	skip := 0
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		var workspace string
		var raw []byte
		msg, err := scanMessageExtra(rows, &workspace, &raw)
		if err != nil {
			return nil, false, err
		}
		if f.To != "" && !recipientMatches(raw, msg.EnvelopeTo, f.To) {
			continue
		}
		if f.Attachments {
			items, _, _ := ScanAttachments(raw, "")
			if len(items) == 0 {
				continue
			}
		}
		if needsMIME && skip < f.Offset {
			skip++
			continue
		}
		if len(out) == f.Limit {
			return out, true, nil
		}
		out = append(out, SearchMatch{Message: *msg, Workspace: workspace})
	}
	return out, false, rows.Err()
}

func recipientMatches(raw []byte, envelope, query string) bool {
	query = strings.ToLower(query)
	if strings.Contains(strings.ToLower(envelope), query) {
		return true
	}
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return false
	}
	for _, header := range []string{"To", "Cc"} {
		for _, value := range m.Header[header] {
			list, err := mail.ParseAddressList(decodeHeader(value))
			if err != nil {
				continue
			}
			for _, a := range list {
				if strings.Contains(strings.ToLower(a.Address), query) {
					return true
				}
			}
		}
	}
	return false
}
