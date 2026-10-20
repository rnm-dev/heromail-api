package calendar

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// Import places an invited event into one of the recipient's own calendars.
// The bearer token must name an address this signed-in user actually controls.
func (s *Store) Import(ctx context.Context, ws, user, token string) (Event, error) {
	cal, err := s.ensure(ctx, ws, user)
	if err != nil {
		return Event{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Event{}, err
	}
	defer tx.Rollback(ctx)
	var eventID, recipient string
	err = tx.QueryRow(ctx, `SELECT event_id,email FROM calendar_attendees WHERE response_token=$1`, token).Scan(&eventID, &recipient)
	if errors.Is(err, pgx.ErrNoRows) {
		return Event{}, ErrNotFound
	}
	if err != nil {
		return Event{}, err
	}
	var controls bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users u WHERE u.id=$1 AND u.email_verified_at IS NOT NULL AND lower(u.email)=$2)
		OR EXISTS(SELECT 1 FROM mailboxes m JOIN domains d ON d.id=m.domain_id WHERE (m.owner_user_id=$1 OR EXISTS(SELECT 1 FROM mailbox_members mm WHERE mm.mailbox_id=m.id AND mm.user_id=$1)) AND lower(m.local_part||'@'||d.domain)=$2)`, user, recipient).Scan(&controls)
	if err != nil {
		return Event{}, err
	}
	if !controls {
		return Event{}, invalid("Приглашение адресовано другому почтовому ящику")
	}
	e, err := scan(tx.QueryRow(ctx, `SELECT `+columns+` FROM calendar_events e WHERE e.id=$1 FOR SHARE`, eventID))
	if err != nil {
		return Event{}, err
	}
	if e.Status != "confirmed" {
		return Event{}, ErrConflict
	}
	_, err = tx.Exec(ctx, `INSERT INTO calendar_imports(calendar_id,event_id,recipient) VALUES($1,$2,$3) ON CONFLICT(calendar_id,event_id) DO UPDATE SET recipient=EXCLUDED.recipient`, cal, eventID, recipient)
	if err != nil {
		return Event{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Event{}, err
	}
	e.Role = "attendee"
	e.InviteToken = token
	e.Attendees = []string{recipient}
	e.Responses = nil
	e.Notifications = nil
	return e, nil
}
