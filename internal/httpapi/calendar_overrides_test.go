package httpapi

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/rnm/heromail/backend/internal/calendar"
	"github.com/rnm/heromail/backend/internal/email"
	"github.com/rnm/heromail/backend/internal/inbound"
)

func TestCalendarChangedOccurrences(t *testing.T) {
	h := newHarness(t)
	t.Setenv("APP_BASE_URL", "https://heromail.test")
	token, userID, _ := h.registerUser("calendar-overrides")
	ws := h.workspaceFor(token, "calendar-overrides")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	domain := h.verifiedDomainFor(t, ws)
	var boxID string
	if err := h.pool.QueryRow(t.Context(), `INSERT INTO mailboxes(domain_id,local_part) SELECT id,'organizer' FROM domains WHERE workspace_id=$1 AND domain=$2 RETURNING id`, ws, domain).Scan(&boxID); err != nil {
		t.Fatal(err)
	}
	address := "organizer@" + domain
	store := calendar.NewStore(h.pool)
	// Mondays 10:00 Almaty from 2030-01-07; the 14th moves to Wednesday 15:00.
	moved := []calendar.Override{{Occurrence: "2030-01-14", Title: "Стендап (перенос)", Start: "2030-01-16T15:00", End: "2030-01-16T15:30"}, {Occurrence: "2030-01-15", Title: "Не повторение", Start: "2030-01-15T10:00", End: "2030-01-15T11:00"}}
	ev, err := store.Save(t.Context(), ws, userID, "", calendar.Input{Title: "Стендап", Timezone: "Asia/Almaty", Start: "2030-01-07T10:00", End: "2030-01-07T10:30",
		RRule: "FREQ=WEEKLY;COUNT=3", Overrides: &moved, Organizer: address, Attendees: []string{"guest@example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	if ev.Overrides == nil || len(*ev.Overrides) != 1 {
		t.Fatalf("non-occurrence override kept: %+v", ev.Overrides)
	}
	list, _, err := store.List(t.Context(), ws, userID, "2030-01-01", "2030-02-01", 0)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range list {
		got = append(got, fmt.Sprintf("%s=%s %s %v", e.Occurrence, e.Start, e.Title, e.Overridden))
	}
	want := "2030-01-07=2030-01-07T10:00 Стендап false,2030-01-21=2030-01-21T10:00 Стендап false,2030-01-14=2030-01-16T15:00 Стендап (перенос) true"
	if strings.Join(got, ",") != want {
		t.Fatalf("occurrences:\n%s\nwant\n%s", strings.Join(got, ","), want)
	}
	if list[2].Master == nil || list[2].Master.Title != "Стендап" || list[2].Master.Start != "2030-01-07T10:00" {
		t.Fatalf("master: %+v", list[2].Master)
	}
	// The moved occurrence shows up in a range that excludes its original date.
	if wed, _, _ := store.List(t.Context(), ws, userID, "2030-01-16", "2030-01-17", 0); len(wed) != 1 || wed[0].Occurrence != "2030-01-14" {
		t.Fatalf("moved occurrence by its new day: %+v", wed)
	}
	dispatcher := calendar.NewDispatcher(h.pool, email.NewService(email.NewStore(h.pool), h.queue, nil).WithDomainGuard(h.domains))
	if ok, err := dispatcher.ProcessEvent(t.Context(), ev.ID); err != nil || !ok {
		t.Fatalf("dispatch %v %v", ok, err)
	}
	var ics string
	h.pool.QueryRow(t.Context(), `SELECT calendar_ics FROM emails WHERE id=(SELECT email_id FROM calendar_jobs WHERE event_id=$1 AND kind='request')`, ev.ID).Scan(&ics)
	if !strings.Contains(ics, "RECURRENCE-ID:20300114T050000Z") || !strings.Contains(ics, "DTSTART:20300116T100000Z") || strings.Count(ics, "BEGIN:VEVENT") != 2 || strings.Count(ics, "ATTENDEE") != 2 {
		t.Fatalf("ics: %s", ics)
	}
	// An edit that does not mention overrides keeps them.
	ev.Title, ev.Overrides = "Стендап команды", nil
	if ev, err = store.Save(t.Context(), ws, userID, ev.ID, ev.Input); err != nil || ev.Overrides == nil || len(*ev.Overrides) != 1 {
		t.Fatalf("kept overrides: %v %+v", err, ev.Overrides)
	}

	// An accepted external series follows a changed and a cancelled occurrence mailed on their own.
	h.pool.Exec(t.Context(), `INSERT INTO calendar_external_events(calendar_id,uid,sequence,attendee,response,organizer_email,title,timezone,all_day,start_at,end_at,rrule)
		SELECT id,'ext-series@example.test',1,$2,'accepted','boss@example.test','Планёрка','Asia/Almaty',false,'2030-02-04 04:00Z','2030-02-04 05:00Z','FREQ=WEEKLY' FROM calendars WHERE workspace_id=$1`, ws, address)
	deliver := func(method, body string) {
		t.Helper()
		raw := itipMail("boss@example.test", address, method, "UID:ext-series@example.test\r\nSEQUENCE:1\r\nORGANIZER:mailto:boss@example.test\r\nATTENDEE:mailto:"+address+"\r\n"+body)
		if _, err := inbound.NewStore(h.pool).Deliver(t.Context(), inbound.DeliverParams{MailboxID: boxID, EnvelopeTo: address, Raw: raw}); err != nil {
			t.Fatal(err)
		}
	}
	deliver("REQUEST", "RECURRENCE-ID:20300211T040000Z\r\nSUMMARY:Планёрка позже\r\nDTSTART:20300211T080000Z\r\nDTEND:20300211T090000Z\r\n")
	deliver("CANCEL", "RECURRENCE-ID:20300218T040000Z\r\nDTSTART:20300218T040000Z\r\n")
	feb, _, err := store.List(t.Context(), ws, userID, "2030-02-01", "2030-02-26", 0)
	if err != nil {
		t.Fatal(err)
	}
	got = nil
	for _, e := range feb {
		if e.UID == "ext-series@example.test" {
			got = append(got, e.Occurrence+"="+e.Start+" "+e.Title)
		}
	}
	if strings.Join(got, ",") != "2030-02-04=2030-02-04T09:00 Планёрка,2030-02-25=2030-02-25T09:00 Планёрка,2030-02-11=2030-02-11T13:00 Планёрка позже" {
		t.Fatalf("external occurrences: %v", got)
	}
}
