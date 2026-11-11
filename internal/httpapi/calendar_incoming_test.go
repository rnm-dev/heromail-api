package httpapi

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/rnm/heromail/backend/internal/calendar"
	"github.com/rnm/heromail/backend/internal/inbound"
)

func itipMail(from, to, method, body string) []byte {
	return []byte(fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: itip\r\nMessage-ID: <%d@x.test>\r\nMIME-Version: 1.0\r\nContent-Type: text/calendar; method=%s\r\n\r\nBEGIN:VCALENDAR\r\nMETHOD:%s\r\nBEGIN:VEVENT\r\n%sEND:VEVENT\r\nEND:VCALENDAR\r\n", from, to, time.Now().UnixNano(), method, method, body))
}

func TestCalendarIncomingReplyCancelAndUpdate(t *testing.T) {
	h := newHarness(t)
	token, userID, _ := h.registerUser("calendar-incoming")
	ws := h.workspaceFor(token, "calendar-incoming")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	domain := h.verifiedDomainFor(t, ws)
	var boxID string
	if err := h.pool.QueryRow(t.Context(), `INSERT INTO mailboxes(domain_id,local_part) SELECT id,'organizer' FROM domains WHERE workspace_id=$1 AND domain=$2 RETURNING id`, ws, domain).Scan(&boxID); err != nil {
		t.Fatal(err)
	}
	address := "organizer@" + domain
	store := calendar.NewStore(h.pool)
	start := time.Now().UTC().Add(3 * time.Hour).Truncate(time.Minute)
	ev, err := store.Save(t.Context(), ws, userID, "", calendar.Input{Title: "Sync", Timezone: "UTC", Start: start.Format("2006-01-02T15:04"), End: start.Add(time.Hour).Format("2006-01-02T15:04"), Organizer: address, Attendees: []string{"guest@example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	deliver := func(raw []byte) {
		t.Helper()
		if _, err := inbound.NewStore(h.pool).Deliver(t.Context(), inbound.DeliverParams{MailboxID: boxID, EnvelopeTo: address, Raw: raw}); err != nil {
			t.Fatal(err)
		}
	}
	response := func() string {
		var r string
		h.pool.QueryRow(t.Context(), `SELECT response FROM calendar_attendees WHERE event_id=$1`, ev.ID).Scan(&r)
		return r
	}
	reply := "UID:" + ev.UID + "\r\nSEQUENCE:0\r\nORGANIZER:mailto:" + address + "\r\nATTENDEE;PARTSTAT=ACCEPTED:mailto:guest@example.test\r\n"
	// A forged sender cannot answer for the attendee.
	deliver(itipMail("mallory@example.test", address, "REPLY", reply))
	if got := response(); got != "needs_action" {
		t.Fatalf("forged reply applied: %s", got)
	}
	deliver(itipMail("guest@example.test", address, "REPLY", reply))
	if got := response(); got != "accepted" {
		t.Fatalf("reply not applied: %s", got)
	}

	// A copy of an external meeting follows a newer REQUEST and goes away on CANCEL.
	invite := "UID:ext-1@example.test\r\nSEQUENCE:%d\r\nSUMMARY:%s\r\nDTSTART:20301010T090000Z\r\nDTEND:20301010T100000Z\r\nORGANIZER:mailto:boss@example.test\r\nATTENDEE:mailto:" + address + "\r\n"
	h.pool.Exec(t.Context(), `INSERT INTO calendar_external_events(calendar_id,uid,sequence,attendee,response,organizer_email,title,timezone,all_day,start_at,end_at)
		SELECT id,'ext-1@example.test',0,$2,'accepted','boss@example.test','Old','UTC',false,'2030-10-10 09:00Z','2030-10-10 10:00Z' FROM calendars WHERE workspace_id=$1`, ws, address)
	title := func() string {
		var s string
		h.pool.QueryRow(t.Context(), `SELECT title FROM calendar_external_events WHERE uid='ext-1@example.test'`).Scan(&s)
		return s
	}
	deliver(itipMail("boss@example.test", address, "REQUEST", fmt.Sprintf(invite, 1, "New")))
	if got := title(); got != "New" {
		t.Fatalf("update not applied: %q", got)
	}
	deliver(itipMail("boss@example.test", address, "REQUEST", fmt.Sprintf(invite, 0, "Stale")))
	if got := title(); got != "New" {
		t.Fatalf("stale update applied: %q", got)
	}
	var copyID string
	h.pool.QueryRow(t.Context(), `SELECT id FROM calendar_external_events WHERE uid='ext-1@example.test'`).Scan(&copyID)
	deliver(itipMail("boss@example.test", address, "CANCEL", fmt.Sprintf(invite, 2, "New")))
	if got := title(); got != "" {
		t.Fatalf("cancel not applied: %q", got)
	}
	if err := store.Delete(t.Context(), ws, userID, copyID, 1); err != calendar.ErrNotFound {
		t.Fatalf("removed copy: %v", err)
	}

	// A cancelled meeting can be removed once the cancellations are out.
	if err := store.Delete(t.Context(), ws, userID, ev.ID, ev.Version); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(t.Context(), ws, userID, ev.ID, ev.Version+1); err == nil {
		t.Fatal("removed before cancellations were sent")
	}
	h.pool.Exec(t.Context(), `UPDATE calendar_jobs SET status='queued' WHERE event_id=$1`, ev.ID)
	if err := store.Delete(t.Context(), ws, userID, ev.ID, ev.Version+1); err != nil {
		t.Fatalf("remove cancelled: %v", err)
	}
}
