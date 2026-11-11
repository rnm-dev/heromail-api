package httpapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rnm/heromail/backend/internal/calendar"
	"github.com/rnm/heromail/backend/internal/email"
)

func TestCalendarRecurrence(t *testing.T) {
	h := newHarness(t)
	t.Setenv("APP_BASE_URL", "https://heromail.test")
	token, userID, _ := h.registerUser("calendar-recur")
	ws := h.workspaceFor(token, "calendar-recur")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	domain := h.verifiedDomainFor(t, ws)
	if _, err := h.pool.Exec(t.Context(), `INSERT INTO mailboxes(domain_id,local_part) SELECT id,'organizer' FROM domains WHERE workspace_id=$1 AND domain=$2`, ws, domain); err != nil {
		t.Fatal(err)
	}
	store := calendar.NewStore(h.pool)
	// Weekly on Mondays from 2030-01-07 10:00 Almaty, four times, skipping the second.
	ev, err := store.Save(t.Context(), ws, userID, "", calendar.Input{Title: "Standup", Timezone: "Asia/Almaty", Start: "2030-01-07T10:00", End: "2030-01-07T10:30",
		RRule: "FREQ=WEEKLY;COUNT=4", Exdates: []string{"2030-01-14"}, Organizer: "organizer@" + domain, Attendees: []string{"guest@example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	list, _, err := store.List(t.Context(), ws, userID, "2030-01-01", "2030-03-01", 0)
	if err != nil {
		t.Fatal(err)
	}
	var days []string
	for _, e := range list {
		days = append(days, e.Occurrence+" "+e.Start)
	}
	if strings.Join(days, ",") != "2030-01-07 2030-01-07T10:00,2030-01-21 2030-01-21T10:00,2030-01-28 2030-01-28T10:00" {
		t.Fatalf("occurrences: %v", days)
	}
	if list[1].SeriesStart != "2030-01-07T10:00" || list[1].StartAt.Format(time.RFC3339) != "2030-01-21T05:00:00Z" {
		t.Fatalf("occurrence: %+v", list[1])
	}
	// The finished series is not loaded for later ranges.
	if later, _, _ := store.List(t.Context(), ws, userID, "2030-03-01", "2030-04-01", 0); len(later) != 0 {
		t.Fatalf("after series end: %+v", later)
	}
	dispatcher := calendar.NewDispatcher(h.pool, email.NewService(email.NewStore(h.pool), h.queue, nil).WithDomainGuard(h.domains))
	if ok, err := dispatcher.ProcessEvent(t.Context(), ev.ID); err != nil || !ok {
		t.Fatalf("dispatch %v %v", ok, err)
	}
	var ics string
	h.pool.QueryRow(t.Context(), `SELECT calendar_ics FROM emails WHERE id=(SELECT email_id FROM calendar_jobs WHERE event_id=$1 AND kind='request')`, ev.ID).Scan(&ics)
	if !strings.Contains(ics, "RRULE:FREQ=WEEKLY;COUNT=4") || !strings.Contains(ics, "EXDATE:20300114T050000Z") || !strings.Contains(ics, "DTSTART:20300107T050000Z") {
		t.Fatalf("ics: %s", ics)
	}

	// Reminders walk the series: each sent reminder schedules the next occurrence's.
	ev.ReminderMinutes, ev.Attendees = 10, nil
	ev, err = store.Save(t.Context(), ws, userID, ev.ID, ev.Input)
	if err != nil {
		t.Fatal(err)
	}
	var due time.Time
	h.pool.QueryRow(t.Context(), `SELECT due_at FROM calendar_jobs WHERE event_id=$1 AND kind='reminder' AND status='pending'`, ev.ID).Scan(&due)
	if due.UTC().Format(time.RFC3339) != "2030-01-07T04:50:00Z" {
		t.Fatalf("first reminder: %v", due)
	}
	h.pool.Exec(t.Context(), `UPDATE calendar_jobs SET due_at=now() WHERE event_id=$1 AND kind='reminder'`, ev.ID)
	for {
		ok, err := dispatcher.ProcessEvent(t.Context(), ev.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
	}
	h.pool.QueryRow(t.Context(), `SELECT due_at FROM calendar_jobs WHERE event_id=$1 AND kind='reminder' AND status='pending'`, ev.ID).Scan(&due)
	if due.UTC().Format(time.RFC3339) != "2030-01-21T04:50:00Z" {
		t.Fatalf("next reminder skips the exdate: %v", due)
	}
	var text string
	h.pool.QueryRow(t.Context(), `SELECT coalesce(text_body,'') FROM emails WHERE subject='Напоминание: Standup'`).Scan(&text)
	if !strings.Contains(text, "7 января 2030, 10:00–10:30") {
		t.Fatalf("reminder text: %q", text)
	}
}
