package httpapi

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rnm/heromail/backend/internal/calendar"
	"github.com/rnm/heromail/backend/internal/inbound"
)

func TestExternalCalendarReply(t *testing.T) {
	h := newHarness(t)
	token, userID, _ := h.registerUser("external-rsvp")
	other, otherID, _ := h.registerUser("external-rsvp-other")
	ws := h.workspaceFor(token, "external-rsvp")
	domain := h.verifiedDomainFor(t, ws)
	path := "/workspaces/" + h.slugFor(ws)
	if _, err := h.pool.Exec(t.Context(), `INSERT INTO workspace_members(workspace_id,user_id,role) VALUES($1,$2,'member')`, ws, otherID); err != nil {
		t.Fatal(err)
	}
	r := h.do("POST", path+"/mailboxes", fmt.Sprintf(`{"domain":%q,"local_part":"me","owner_user_id":%q}`, domain, userID), token)
	if r.Code != 201 {
		t.Fatalf("box %d %s", r.Code, r.Body)
	}
	var box Mailbox
	if err := json.Unmarshal(r.Body.Bytes(), &box); err != nil {
		t.Fatal(err)
	}
	address := string(box.Address)
	deliver := func(attendee string) string {
		ics := "BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:ext-1\r\nSEQUENCE:0\r\nSUMMARY:Sync\r\n" +
			"ORGANIZER;CN=Org:MAILTO:org@bank.test\r\nATTENDEE;RSVP=TRUE:MAILTO:" + strings.ToUpper(attendee) + "\r\n" +
			"DTSTART:20261015T120000Z\r\nDTEND:20261015T123000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
		raw := "From: org@bank.test\r\nMessage-ID: <invite-" + attendee + "@bank.test>\r\nSubject: Sync\r\nContent-Type: multipart/alternative; boundary=b\r\n\r\n" +
			"--b\r\nContent-Type: text/plain\r\n\r\nJoin us\r\n--b\r\nContent-Type: text/calendar; method=REQUEST\r\n\r\n" + ics + "--b--\r\n"
		msg, err := inbound.NewStore(h.pool).Deliver(t.Context(), inbound.DeliverParams{MailboxID: box.Id.String(), EnvelopeTo: address, Raw: []byte(raw)})
		if err != nil {
			t.Fatal(err)
		}
		return msg.ID
	}
	id := deliver(address)
	detail := func() CalendarPreview {
		r := h.do("GET", path+"/messages/"+id, "", token)
		var m ReceivedMessage
		if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &m) != nil || m.CalendarPreview == nil {
			t.Fatalf("detail %d %s", r.Code, r.Body)
		}
		return *m.CalendarPreview
	}
	if p := detail(); p.Attendee == nil || *p.Attendee != address || p.Response != nil || p.Organizer != "org@bank.test" {
		t.Fatalf("preview %+v", p)
	}
	reply := path + "/messages/" + id + "/calendar-reply"
	if r = h.do("POST", reply, `{"response":"accepted"}`, other); r.Code != 404 {
		t.Fatalf("other member answered a private invite: %d", r.Code)
	}
	if r = h.do("POST", reply, `{"response":"maybe"}`, token); r.Code != 400 {
		t.Fatalf("bad response %d", r.Code)
	}
	if r = h.do("POST", reply, `{"response":"accepted"}`, token); r.Code != 200 {
		t.Fatalf("reply %d %s", r.Code, r.Body)
	}
	if p := detail(); p.Response == nil || *p.Response != Accepted {
		t.Fatalf("response not recorded %+v", p)
	}
	var to, subject, method, ics, inReplyTo string
	if err := h.pool.QueryRow(t.Context(), `SELECT to_addrs[1],subject,calendar_method,calendar_ics,coalesce(in_reply_to,'') FROM emails WHERE workspace_id=$1 AND from_addr=$2`, ws, address).Scan(&to, &subject, &method, &ics, &inReplyTo); err != nil {
		t.Fatal(err)
	}
	if to != "org@bank.test" || method != "REPLY" || subject != "Принято: Sync" || inReplyTo != "<invite-"+address+"@bank.test>" ||
		!strings.Contains(ics, "ATTENDEE;PARTSTAT=ACCEPTED:mailto:"+address) || !strings.Contains(ics, "UID:ext-1") {
		t.Fatalf("sent %s %s %s %s\n%s", to, subject, method, inReplyTo, ics)
	}
	events := func() []calendar.Event {
		r := h.do("GET", path+"/calendar/events?from=2026-10-14&to=2026-10-17", "", token)
		var body struct {
			Events []calendar.Event `json:"events"`
		}
		if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &body) != nil {
			t.Fatalf("list %d: %s", r.Code, r.Body)
		}
		return body.Events
	}
	if list := events(); len(list) != 1 || list[0].Title != "Sync" || list[0].Role != "attendee" || !list[0].StartAt.Equal(time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)) || list[0].Responses[0].Response != "accepted" {
		t.Fatalf("accepted invite not in calendar: %+v", list)
	}
	if r = h.do("POST", reply, `{"response":"accepted"}`, token); r.Code != 200 {
		t.Fatalf("repeat %d", r.Code)
	}
	if list := events(); len(list) != 1 {
		t.Fatalf("repeat duplicated the event: %+v", list)
	}
	if r = h.do("POST", reply, `{"response":"declined"}`, token); r.Code != 200 {
		t.Fatalf("change %d %s", r.Code, r.Body)
	}
	var count int
	if err := h.pool.QueryRow(t.Context(), `SELECT count(*) FROM emails WHERE workspace_id=$1 AND calendar_method='REPLY'`, ws).Scan(&count); err != nil || count != 2 {
		t.Fatalf("replies=%d err=%v", count, err)
	}
	if p := detail(); *p.Response != Declined {
		t.Fatalf("change not recorded %+v", p)
	}
	if list := events(); len(list) != 0 {
		t.Fatalf("declined invite stayed in calendar: %+v", list)
	}

	// An invitation addressed to somebody else cannot be answered from this mailbox.
	id = deliver("someone@bank.test")
	if p := detail(); p.Attendee != nil {
		t.Fatalf("foreign invite offered reply %+v", p)
	}
	if r = h.do("POST", path+"/messages/"+id+"/calendar-reply", `{"response":"accepted"}`, token); r.Code != 400 {
		t.Fatalf("foreign invite %d", r.Code)
	}
}
