package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rnm/heromail/backend/internal/calendar"
	"github.com/rnm/heromail/backend/internal/email"
)

func TestCalendarJobFailureBecomesVisibleAfterRetryBudget(t *testing.T) {
	h := newHarness(t)
	t.Setenv("APP_BASE_URL", "https://heromail.test")
	token, userID, _ := h.registerUser("calendar-job-dead")
	ws := h.workspaceFor(token, "calendar-job-dead")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	domain := h.verifiedDomainFor(t, ws)
	if _, err := h.pool.Exec(t.Context(), `INSERT INTO mailboxes(domain_id,local_part) SELECT id,'organizer' FROM domains WHERE workspace_id=$1 AND domain=$2`, ws, domain); err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Add(3 * time.Hour).Truncate(time.Minute)
	input := calendar.Input{Title: "Job failure", Timezone: "UTC", Start: start.Format("2006-01-02T15:04"), End: start.Add(time.Hour).Format("2006-01-02T15:04"), Organizer: "organizer@" + domain, Attendees: []string{"guest@example.test"}}
	created, err := calendar.NewStore(h.pool).Save(t.Context(), ws, userID, "", input)
	if err != nil {
		t.Fatal(err)
	}
	h.queue.err = errors.New("queue offline")
	dispatcher := calendar.NewDispatcher(h.pool, email.NewService(email.NewStore(h.pool), h.queue, nil).WithDomainGuard(h.domains))
	for i := 0; i < 8; i++ {
		if ok, err := dispatcher.ProcessEvent(t.Context(), created.ID); !ok || err == nil {
			t.Fatalf("attempt %d: ok=%v err=%v", i, ok, err)
		}
		if _, err := h.pool.Exec(t.Context(), `UPDATE calendar_jobs SET due_at=now() WHERE event_id=$1`, created.ID); err != nil {
			t.Fatal(err)
		}
	}
	var status string
	if err := h.pool.QueryRow(t.Context(), `SELECT status FROM calendar_jobs WHERE event_id=$1`, created.ID).Scan(&status); err != nil || status != "dead" {
		t.Fatalf("status=%s err=%v", status, err)
	}
	if ok, err := dispatcher.ProcessEvent(t.Context(), created.ID); ok || err != nil {
		t.Fatalf("dead job retried: ok=%v err=%v", ok, err)
	}
}

func TestCalendarInvitationResponseAndCancellation(t *testing.T) {
	h := newHarness(t)
	t.Setenv("APP_BASE_URL", "https://heromail.test")
	token, _, _ := h.registerUser("calendar-invite")
	ws := h.workspaceFor(token, "calendar-invite")
	t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	path := "/workspaces/" + h.slugFor(ws) + "/calendar/events"
	domain := h.verifiedDomainFor(t, ws)
	from := "organizer@" + domain
	if _, err := h.pool.Exec(t.Context(), `INSERT INTO mailboxes(domain_id,local_part) SELECT id,'organizer' FROM domains WHERE workspace_id=$1 AND domain=$2`, ws, domain); err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Add(3 * time.Hour).Truncate(time.Minute)
	input := calendar.Input{Title: "Planning", Timezone: "UTC", Start: start.Format("2006-01-02T15:04"), End: start.Add(time.Hour).Format("2006-01-02T15:04"), Organizer: from, Attendees: []string{"guest@example.test"}, ReminderMinutes: 30}
	body, _ := json.Marshal(input)
	r := h.do("POST", path, string(body), token)
	if r.Code != 201 {
		t.Fatalf("create %d: %s", r.Code, r.Body)
	}
	var event calendar.Event
	if err := json.Unmarshal(r.Body.Bytes(), &event); err != nil {
		t.Fatal(err)
	}
	if event.UID == "" || len(event.Attendees) != 1 || event.Sequence != 0 {
		t.Fatalf("event: %+v", event)
	}
	var responseToken string
	if err := h.pool.QueryRow(t.Context(), `SELECT response_token::text FROM calendar_attendees WHERE event_id=$1`, event.ID).Scan(&responseToken); err != nil {
		t.Fatal(err)
	}
	var jobs int
	if err := h.pool.QueryRow(t.Context(), `SELECT count(*) FROM calendar_jobs WHERE event_id=$1`, event.ID).Scan(&jobs); err != nil || jobs != 2 {
		t.Fatalf("jobs %d: %v", jobs, err)
	}
	dispatcher := calendar.NewDispatcher(h.pool, email.NewService(email.NewStore(h.pool), h.queue, nil).WithDomainGuard(h.domains))
	if ok, err := dispatcher.ProcessEvent(t.Context(), event.ID); err != nil || !ok {
		t.Fatalf("dispatch %v %v", ok, err)
	}
	var outgoing email.Email
	if err := h.pool.QueryRow(t.Context(), `SELECT calendar_ics,calendar_method FROM emails WHERE id=(SELECT email_id FROM calendar_jobs WHERE event_id=$1 AND kind='request')`, event.ID).Scan(&outgoing.CalendarICS, &outgoing.CalendarMethod); err != nil {
		t.Fatal(err)
	}
	if outgoing.CalendarMethod != "REQUEST" || !strings.Contains(outgoing.CalendarICS, "UID:"+event.UID) {
		t.Fatalf("ics: %+v", outgoing)
	}
	var emailID string
	if err := h.pool.QueryRow(t.Context(), `SELECT email_id::text FROM calendar_jobs WHERE event_id=$1 AND kind='request'`, event.ID).Scan(&emailID); err != nil {
		t.Fatal(err)
	}
	if err := h.worker.Deliver(t.Context(), emailID, 0, 8); err != nil {
		t.Fatal(err)
	}
	if sent, ok := h.mail.last(); !ok || sent.CalendarMethod != "REQUEST" || len(sent.To) != 1 || sent.To[0] != "guest@example.test" {
		t.Fatalf("delivered invitation: %+v", sent)
	}
	invitePath := "/calendar/invite/" + responseToken
	if r = h.do("GET", invitePath, "", ""); r.Code != 200 {
		t.Fatalf("public invite %d: %s", r.Code, r.Body)
	}
	if r = h.do("POST", invitePath, `{"response":"accepted"}`, ""); r.Code != 200 {
		t.Fatalf("response %d: %s", r.Code, r.Body)
	}
	if r = h.do("POST", invitePath, `{"response":"accepted"}`, ""); r.Code != 200 {
		t.Fatalf("repeated response %d: %s", r.Code, r.Body)
	}
	if err := h.pool.QueryRow(t.Context(), `SELECT count(*) FROM calendar_jobs WHERE event_id=$1 AND kind='reply'`, event.ID).Scan(&jobs); err != nil || jobs != 1 {
		t.Fatalf("reply jobs %d: %v", jobs, err)
	}
	input.Version = event.Version
	input.Title = "Planning moved"
	body, _ = json.Marshal(input)
	if r = h.do("PUT", path+"/"+event.ID, string(body), token); r.Code != 200 {
		t.Fatalf("update %d: %s", r.Code, r.Body)
	}
	var oldReminder, newReminder string
	if err := h.pool.QueryRow(t.Context(), `SELECT status FROM calendar_jobs WHERE event_id=$1 AND kind='reminder' AND event_version=1`, event.ID).Scan(&oldReminder); err != nil {
		t.Fatal(err)
	}
	if err := h.pool.QueryRow(t.Context(), `SELECT status FROM calendar_jobs WHERE event_id=$1 AND kind='reminder' AND event_version=2`, event.ID).Scan(&newReminder); err != nil {
		t.Fatal(err)
	}
	if oldReminder != "skipped" || newReminder != "pending" {
		t.Fatalf("reminder reschedule: old=%s new=%s", oldReminder, newReminder)
	}
	if r = h.do("GET", invitePath, "", ""); r.Code != 200 {
		t.Fatal(r.Code)
	}
	var invite calendar.Invitation
	if err := json.Unmarshal(r.Body.Bytes(), &invite); err != nil {
		t.Fatal(err)
	}
	if invite.Response != "needs_action" || invite.Event.Sequence != 1 {
		t.Fatalf("updated invite %+v", invite)
	}
	if r = h.do("DELETE", fmt.Sprintf("%s/%s?version=2", path, event.ID), "", token); r.Code != 204 {
		t.Fatalf("cancel %d: %s", r.Code, r.Body)
	}
	if err := h.pool.QueryRow(t.Context(), `SELECT status FROM calendar_jobs WHERE event_id=$1 AND kind='reminder' AND event_version=2`, event.ID).Scan(&newReminder); err != nil || newReminder != "skipped" {
		t.Fatalf("cancelled reminder %q: %v", newReminder, err)
	}
	if r = h.do("POST", invitePath, `{"response":"accepted"}`, ""); r.Code != 409 {
		t.Fatalf("accepted cancelled event: %d", r.Code)
	}
}

func TestCalendarImportTracksOrganizerWithoutLeakingOtherAttendees(t *testing.T) {
	h := newHarness(t)
	ownerToken, ownerID, _ := h.registerUser("calendar-import-owner")
	guestToken, _, guestEmail := h.registerUser("calendar-import-guest")
	otherToken, _, _ := h.registerUser("calendar-import-other")
	ownerWS := h.workspaceFor(ownerToken, "calendar-import-owner")
	guestWS := h.workspaceFor(guestToken, "calendar-import-guest")
	otherWS := h.workspaceFor(otherToken, "calendar-import-other")
	for _, ws := range []string{ownerWS, guestWS, otherWS} {
		ws := ws
		t.Cleanup(func() { h.pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id=$1`, ws) })
	}
	if _, err := h.pool.Exec(t.Context(), `UPDATE users SET email_verified_at=now() WHERE email=$1`, guestEmail); err != nil {
		t.Fatal(err)
	}
	domain := h.verifiedDomainFor(t, ownerWS)
	if _, err := h.pool.Exec(t.Context(), `INSERT INTO mailboxes(domain_id,local_part) SELECT id,'host' FROM domains WHERE workspace_id=$1 AND domain=$2`, ownerWS, domain); err != nil {
		t.Fatal(err)
	}
	start := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Minute)
	input := calendar.Input{Title: "Shared planning", Timezone: "UTC", Start: start.Format("2006-01-02T15:04"), End: start.Add(time.Hour).Format("2006-01-02T15:04"), Organizer: "host@" + domain, Attendees: []string{guestEmail, "secret@example.test"}}
	event, err := calendar.NewStore(h.pool).Save(t.Context(), ownerWS, ownerID, "", input)
	if err != nil {
		t.Fatal(err)
	}
	var inviteToken string
	if err := h.pool.QueryRow(t.Context(), `SELECT response_token::text FROM calendar_attendees WHERE event_id=$1 AND email=$2`, event.ID, guestEmail).Scan(&inviteToken); err != nil {
		t.Fatal(err)
	}
	path := "/workspaces/" + h.slugFor(guestWS) + "/calendar/imports/" + inviteToken
	if r := h.do("POST", path, "", otherToken); r.Code == 200 {
		t.Fatal("unrelated user imported invite")
	}
	if r := h.do("POST", path, "", guestToken); r.Code != 200 {
		t.Fatalf("import %d: %s", r.Code, r.Body)
	}
	list := fmt.Sprintf("/workspaces/%s/calendar/events?from=%s&to=%s", h.slugFor(guestWS), start.Format("2006-01-02"), start.Add(48*time.Hour).Format("2006-01-02"))
	read := func() calendar.Event {
		r := h.do("GET", list, "", guestToken)
		var body struct {
			Events []calendar.Event `json:"events"`
		}
		if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &body) != nil || len(body.Events) != 1 {
			t.Fatalf("list %d: %s", r.Code, r.Body)
		}
		return body.Events[0]
	}
	copy := read()
	if copy.Role != "attendee" || copy.InviteToken != inviteToken || len(copy.Attendees) != 1 || copy.Attendees[0] != guestEmail || len(copy.Notifications) != 0 {
		t.Fatalf("private copy: %+v", copy)
	}
	input.Version = event.Version
	input.Title = "Moved planning"
	if _, err := calendar.NewStore(h.pool).Save(t.Context(), ownerWS, ownerID, event.ID, input); err != nil {
		t.Fatal(err)
	}
	if copy = read(); copy.Title != "Moved planning" || copy.Sequence != 1 {
		t.Fatalf("stale copy: %+v", copy)
	}
	if err := calendar.NewStore(h.pool).Delete(t.Context(), ownerWS, ownerID, event.ID, 2); err != nil {
		t.Fatal(err)
	}
	if copy = read(); copy.Status != "cancelled" {
		t.Fatalf("uncancelled copy: %+v", copy)
	}
}
