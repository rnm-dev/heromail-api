package httpapi

import (
	"context"
	"testing"
	"time"

	"github.com/rnm/heromail/backend/internal/calendar"
	"github.com/rnm/heromail/backend/internal/email"
)

func TestCalendarCopyReminder(t *testing.T) {
	h := newHarness(t)
	token, userID, _ := h.registerUser("calendar-copy-reminder")
	ws := h.workspaceFor(token, "calendar-copy-reminder")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	domain := h.verifiedDomainFor(t, ws)
	address := "me@" + domain
	if _, err := h.pool.Exec(t.Context(), `INSERT INTO mailboxes(domain_id,local_part,owner_user_id) SELECT id,'me',$3 FROM domains WHERE workspace_id=$1 AND domain=$2`, ws, domain, userID); err != nil {
		t.Fatal(err)
	}
	store := calendar.NewStore(h.pool)
	store.Settings(t.Context(), ws, userID, nil)
	start := time.Now().UTC().Add(40 * time.Minute).Truncate(time.Minute)
	var id string
	if err := h.pool.QueryRow(t.Context(), `INSERT INTO calendar_external_events(calendar_id,uid,attendee,response,organizer_email,title,timezone,all_day,start_at,end_at)
		SELECT id,'ext-rem@example.test',$2,'accepted','boss@example.test','Review','UTC',false,$3,$4 FROM calendars WHERE workspace_id=$1 RETURNING id`, ws, address, start, start.Add(time.Hour)).Scan(&id); err != nil {
		t.Fatal(err)
	}
	path := "/workspaces/" + h.slugFor(ws) + "/calendar/events/" + id + "/reminder"
	if r := h.do("PUT", path, `{"reminder_minutes":15}`, token); r.Code != 400 {
		t.Fatalf("bad minutes: %d", r.Code)
	}
	if r := h.do("PUT", path, `{"reminder_minutes":30}`, token); r.Code != 204 {
		t.Fatalf("set: %d %s", r.Code, r.Body)
	}
	list, _, _ := store.List(t.Context(), ws, userID, start.AddDate(0, 0, -1).Format("2006-01-02"), start.AddDate(0, 0, 2).Format("2006-01-02"), 0)
	if len(list) != 1 || list[0].ReminderMinutes != 30 {
		t.Fatalf("list: %+v", list)
	}
	reminders := calendar.NewCopyReminders(store, email.NewService(email.NewStore(h.pool), h.queue, nil).WithDomainGuard(h.domains))
	for i := 0; i < 2; i++ {
		if err := reminders.RunOnce(t.Context(), time.Now().Add(15*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	var sent int
	h.pool.QueryRow(t.Context(), `SELECT count(*) FROM emails WHERE subject='Напоминание: Review' AND from_addr=$1`, address).Scan(&sent)
	if sent != 1 {
		t.Fatalf("reminders sent: %d", sent)
	}
}
