package calendar

import (
	"strings"
	"testing"
	"time"
)

// Shaped like an Exchange 2010 invitation: quoted parameters, folded lines,
// upper-case MAILTO and a Windows time zone name defined in VTIMEZONE.
const exchangeInvite = "BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nPRODID:Microsoft Exchange Server 2010\r\nVERSION:2.0\r\n" +
	"BEGIN:VTIMEZONE\r\nTZID:Qyzylorda Standard Time\r\nBEGIN:STANDARD\r\nDTSTART:16010101T000000\r\nTZOFFSETFROM:+0500\r\nTZOFFSETTO:+0500\r\nEND:STANDARD\r\nEND:VTIMEZONE\r\n" +
	"BEGIN:VEVENT\r\nORGANIZER;CN=\"Org: Name\":MAILTO:Organizer@Bank.test\r\n" +
	"ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;CN=me@rnm.te\r\n st:MAILTO:Me@rnm.test\r\n" +
	"ATTENDEE;PARTSTAT=NEEDS-ACTION;CN=Other:MAILTO:other@bank.test\r\n" +
	"UID:0400000082\r\n 00E0\r\nSUMMARY;LANGUAGE=ru-RU:Проект \"Карта\\, офферов\"\r\n" +
	"DTSTART;TZID=Qyzylorda Standard Time:20261015T170000\r\nDTEND;TZID=Qyzylorda Standard Time:20261015T173000\r\n" +
	"SEQUENCE:2\r\nBEGIN:VALARM\r\nTRIGGER:-PT15M\r\nACTION:DISPLAY\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"

func TestExternalInviteReply(t *testing.T) {
	invite, err := ParseExternalInvite([]byte(exchangeInvite))
	if err != nil {
		t.Fatal(err)
	}
	if invite.Organizer != "organizer@bank.test" || invite.UID != "040000008200E0" || invite.Sequence != "2" || invite.Title != "Проект \"Карта, офферов\"" {
		t.Fatalf("parsed %+v", invite)
	}
	if !invite.Invites("me@RNM.test") || invite.Invites("stranger@rnm.test") {
		t.Fatalf("attendees %v", invite.Attendees)
	}
	stamp := time.Date(2026, 10, 14, 9, 0, 0, 0, time.UTC)
	reply, err := invite.Reply("me@rnm.test", "accepted", stamp)
	if err != nil {
		t.Fatal(err)
	}
	unfolded := strings.ReplaceAll(reply, "\r\n ", "")
	for _, want := range []string{"METHOD:REPLY", "UID:040000008200E0", "SEQUENCE:2", "DTSTAMP:20261014T090000Z",
		"ATTENDEE;PARTSTAT=ACCEPTED:mailto:me@rnm.test", "ORGANIZER;CN=\"Org: Name\":MAILTO:Organizer@Bank.test",
		"DTSTART;TZID=Qyzylorda Standard Time:20261015T170000", "BEGIN:VTIMEZONE\r\nTZID:Qyzylorda Standard Time", "END:VTIMEZONE"} {
		if !strings.Contains(unfolded, want) {
			t.Errorf("reply lacks %q:\n%s", want, reply)
		}
	}
	for _, leaked := range []string{"other@bank.test", "VALARM", "NEEDS-ACTION"} {
		if strings.Contains(unfolded, leaked) {
			t.Errorf("reply contains %q", leaked)
		}
	}
	for _, line := range strings.Split(reply, "\r\n") {
		if len(line) > 75 {
			t.Errorf("unfolded line %q", line)
		}
	}
	if _, err := invite.Reply("stranger@rnm.test", "accepted", stamp); err == nil {
		t.Fatal("reply for a non-attendee")
	}
	if _, err := invite.Reply("me@rnm.test", "maybe", stamp); err == nil {
		t.Fatal("unknown response accepted")
	}
}

func TestExternalInviteRejectsUnsupportedShapes(t *testing.T) {
	for name, ics := range map[string]string{
		"cancel":    strings.Replace(exchangeInvite, "METHOD:REQUEST", "METHOD:CANCEL", 1),
		"recurring": strings.Replace(exchangeInvite, "SEQUENCE:2", "SEQUENCE:2\r\nRRULE:FREQ=WEEKLY", 1),
		"two":       strings.Replace(exchangeInvite, "END:VCALENDAR", "BEGIN:VEVENT\r\nUID:x\r\nEND:VEVENT\r\nEND:VCALENDAR", 1),
		"unclosed":  strings.Replace(exchangeInvite, "END:VALARM\r\n", "", 1),
		"no-org":    strings.Replace(exchangeInvite, "MAILTO:Organizer@Bank.test", "MAILTO:nobody", 1),
	} {
		if _, err := ParseExternalInvite([]byte(ics)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
