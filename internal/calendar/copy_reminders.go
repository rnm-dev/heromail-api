package calendar

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/email"
)

// SetCopyReminder sets the caller's reminder on a copy of another person's
// meeting in their calendar: a Heromail import (by event id) or an accepted
// external invitation (by copy id).
func (s *Store) SetCopyReminder(ctx context.Context, ws, user, id string, minutes int) error {
	if minutes != 0 && minutes != 10 && minutes != 30 && minutes != 60 {
		return invalid("Напоминание должно быть выключено или за 10, 30, 60 минут")
	}
	tag, err := s.pool.Exec(ctx, `UPDATE calendar_imports i SET reminder_minutes=$4,reminded_until=now() FROM calendars c
		WHERE c.id=i.calendar_id AND c.workspace_id=$1 AND c.user_id=$2 AND i.event_id::text=$3`, ws, user, id, minutes)
	if err != nil {
		return err
	}
	if tag.RowsAffected() > 0 {
		return nil
	}
	tag, err = s.pool.Exec(ctx, `UPDATE calendar_external_events x SET reminder_minutes=$4,reminded_until=now() FROM calendars c
		WHERE c.id=x.calendar_id AND c.workspace_id=$1 AND c.user_id=$2 AND x.id::text=$3`, ws, user, id, minutes)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CopyReminders mails participants their own reminders, from and to the
// address that was invited. A reminder more than an hour late is skipped.
type CopyReminders struct {
	store  *Store
	emails *email.Service
}

func NewCopyReminders(store *Store, emails *email.Service) *CopyReminders {
	return &CopyReminders{store: store, emails: emails}
}

func (c *CopyReminders) Run(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		if err := c.RunOnce(ctx, time.Now()); err != nil {
			log.Printf("calendar copy reminders: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

type copyDue struct {
	table, id, ws, to, user string
	event                   Event
	after                   time.Time
}

func (c *CopyReminders) RunOnce(ctx context.Context, now time.Time) error {
	rows, err := c.store.pool.Query(ctx, `
		SELECT 'calendar_imports', i.calendar_id::text||'/'||i.event_id::text, cal.workspace_id::text, cal.user_id::text, i.recipient, i.reminder_minutes, i.reminded_until, `+columns+`
		FROM calendar_imports i JOIN calendars cal ON cal.id=i.calendar_id JOIN calendar_events e ON e.id=i.event_id
		WHERE i.reminder_minutes>0 AND e.status='confirmed'
		UNION ALL
		SELECT 'calendar_external_events', x.id::text, cal.workspace_id::text, cal.user_id::text, x.attendee, x.reminder_minutes, x.reminded_until,
		x.id,x.title,x.description,x.location,x.timezone,x.all_day,x.start_at,x.end_at,x.start_date::text,x.end_date::text,1,x.organizer_email,x.uid,x.sequence,'confirmed',x.reminder_minutes,x.updated_at,x.rrule,x.exdates,'',x.overrides,''
		FROM calendar_external_events x JOIN calendars cal ON cal.id=x.calendar_id WHERE x.reminder_minutes>0`)
	if err != nil {
		return err
	}
	var due []copyDue
	for rows.Next() {
		var d copyDue
		var minutes int
		var start, end *string
		var overrides []byte
		e := &d.event
		if err = rows.Scan(&d.table, &d.id, &d.ws, &d.user, &d.to, &minutes, &d.after, &e.ID, &e.Title, &e.Description, &e.Location, &e.Timezone, &e.AllDay, &e.StartAt, &e.EndAt, &start, &end, &e.Version, &e.Organizer, &e.UID, &e.Sequence, &e.Status, &e.ReminderMinutes, &e.UpdatedAt, &e.RRule, &e.Exdates, &e.Color, &overrides, &e.RoomID); err != nil {
			rows.Close()
			return err
		}
		if err = decodeOverrides(overrides, &e.Input); err != nil {
			rows.Close()
			return err
		}
		e.ReminderMinutes = minutes
		if e.AllDay {
			e.Start, e.End = *start, *end
		}
		due = append(due, d)
	}
	rows.Close()
	for _, d := range due {
		at, ok := nextReminder(d.event, d.after)
		if !ok || at.After(now) {
			continue
		}
		if now.Sub(at) < time.Hour {
			e := atOccurrence(d.event, at)
			text := e.Title + "\n" + HumanRange(e)
			if e.Location != "" {
				text += "\nМесто: " + e.Location
			}
			key := fmt.Sprintf("calendar-copy-reminder-%s-%d", d.id, at.Unix()/60)
			if _, err := c.emails.Send(account.ContextWithUser(ctx, &account.User{ID: d.user}), d.ws, key, email.SendRequest{From: d.to, To: []string{d.to}, Subject: "Напоминание: " + e.Title, Text: text}); err != nil {
				log.Printf("calendar copy reminder %s: %v", d.id, err)
				continue
			}
		}
		where := "event_id::text=split_part($2,'/',2) AND calendar_id::text=split_part($2,'/',1)"
		if d.table == "calendar_external_events" {
			where = "id::text=$2"
		}
		if _, err := c.store.pool.Exec(ctx, `UPDATE `+d.table+` SET reminded_until=$1 WHERE `+where, at, d.id); err != nil {
			return err
		}
	}
	return nil
}
