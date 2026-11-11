package calendar

import (
	"context"
	"strings"
	"time"
)

// Busy is one occupied interval, without any detail of the event behind it.
type Busy struct {
	AllDay  bool       `json:"all_day"`
	Start   string     `json:"start,omitempty"`
	End     string     `json:"end,omitempty"`
	StartAt *time.Time `json:"start_at,omitempty"`
	EndAt   *time.Time `json:"end_at,omitempty"`
}

// BusyTimes reports when the caller ("") and workspace colleagues behind the
// given addresses are occupied. Only members of the same workspace resolve,
// through their sign-in address or a private mailbox they own; others are
// absent. Titles and other details never leave the owner's calendar.
func (s *Store) BusyTimes(ctx context.Context, ws, user, from, to, exclude string, emails []string) (map[string][]Busy, error) {
	if len(emails) > 20 {
		return nil, invalid("Не больше 20 адресов")
	}
	for i := range emails {
		emails[i] = strings.ToLower(strings.TrimSpace(emails[i]))
	}
	owners := map[string]string{"": user}
	rows, err := s.pool.Query(ctx, `SELECT lower(u.email),u.id::text FROM users u JOIN workspace_members wm ON wm.user_id=u.id AND wm.workspace_id=$1 WHERE lower(u.email)=ANY($2)
		UNION SELECT lower(m.local_part||'@'||d.domain),m.owner_user_id::text FROM mailboxes m JOIN domains d ON d.id=m.domain_id
		JOIN workspace_members wm ON wm.user_id=m.owner_user_id AND wm.workspace_id=$1 WHERE lower(m.local_part||'@'||d.domain)=ANY($2)`, ws, emails)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var addr, id string
		if err = rows.Scan(&addr, &id); err != nil {
			rows.Close()
			return nil, err
		}
		owners[addr] = id
	}
	rows.Close()
	out := map[string][]Busy{}
	cache := map[string][]Busy{}
	for addr, id := range owners {
		if busy, ok := cache[id]; ok {
			out[addr] = busy
			continue
		}
		busy := []Busy{}
		for offset := 0; ; {
			page, more, err := s.List(ctx, ws, id, from, to, offset)
			if err != nil {
				return nil, err
			}
			for _, e := range page {
				if e.Status == "cancelled" || (exclude != "" && e.ID == exclude) {
					continue
				}
				b := Busy{AllDay: e.AllDay}
				if e.AllDay {
					b.Start, b.End = e.Start, e.End
				} else {
					b.StartAt, b.EndAt = e.StartAt, e.EndAt
				}
				busy = append(busy, b)
			}
			if !more || offset > 2000 {
				break
			}
			offset += len(page)
		}
		cache[id] = busy
		out[addr] = busy
	}
	return out, nil
}
