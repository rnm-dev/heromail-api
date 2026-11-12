package calendar

import (
	"context"
	"strings"
	"unicode/utf8"
)

// Search finds the caller's events (own, Heromail imports and accepted external
// copies) whose title, place or description contains q; newest first, at most 50.
// Repeating events are returned once, as their series.
func (s *Store) Search(ctx context.Context, ws, user, q string) ([]Event, error) {
	q = strings.TrimSpace(q)
	if n := utf8.RuneCountInString(q); n < 2 || n > 100 {
		return nil, invalid("Запрос — от 2 до 100 символов")
	}
	match := func(t string) string {
		return `strpos(lower(concat_ws(' ',` + t + `.title,` + t + `.location,` + t + `.description)),lower($3))>0`
	}
	rows, err := s.pool.Query(ctx, `SELECT * FROM (
		SELECT `+columns+`, 'organizer'::text AS role, ''::text AS token, ''::text AS recipient, ''::text AS response,coalesce(e.start_at,e.start_date::timestamp AT TIME ZONE 'UTC') AS sort_at
		FROM calendar_events e JOIN calendars c ON c.id=e.calendar_id WHERE c.workspace_id=$1 AND c.user_id=$2 AND `+match("e")+`
		UNION ALL
		SELECT `+strings.Replace(columns, "e.reminder_minutes", "i.reminder_minutes", 1)+`, 'attendee'::text, a.response_token::text,i.recipient,a.response,coalesce(e.start_at,e.start_date::timestamp AT TIME ZONE 'UTC')
		FROM calendar_imports i JOIN calendars c ON c.id=i.calendar_id JOIN calendar_events e ON e.id=i.event_id
		JOIN calendar_attendees a ON a.event_id=i.event_id AND a.email=i.recipient
		WHERE c.workspace_id=$1 AND c.user_id=$2 AND `+match("e")+`
		UNION ALL
		SELECT x.id,x.title,x.description,x.location,x.timezone,x.all_day,x.start_at,x.end_at,x.start_date::text,x.end_date::text,1,x.organizer_email,x.uid,x.sequence,'confirmed'::text,x.reminder_minutes,x.updated_at,x.rrule,x.exdates,''::text,
		'attendee'::text,''::text,x.attendee,x.response,coalesce(x.start_at,x.start_date::timestamp AT TIME ZONE 'UTC')
		FROM calendar_external_events x JOIN calendars c ON c.id=x.calendar_id
		WHERE c.workspace_id=$1 AND c.user_id=$2 AND `+match("x")+`
	) items ORDER BY sort_at DESC,id LIMIT 50`, ws, user, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		e, err := scanList(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
