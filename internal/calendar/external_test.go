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
		"recurring": strings.Replace(exchangeInvite, "SEQUENCE:2", "SEQUENCE:2\r\nRRULE:FREQ=WEEKLY;BYSETPOS=1", 1),
		"two":       strings.Replace(exchangeInvite, "END:VCALENDAR", "BEGIN:VEVENT\r\nUID:x\r\nEND:VEVENT\r\nEND:VCALENDAR", 1),
		"unclosed":  strings.Replace(exchangeInvite, "END:VALARM\r\n", "", 1),
		"no-org":    strings.Replace(exchangeInvite, "MAILTO:Organizer@Bank.test", "MAILTO:nobody", 1),
	} {
		if _, err := ParseExternalInvite([]byte(ics)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestExternalInviteTimes(t *testing.T) {
	almaty, _ := time.LoadLocation("Asia/Almaty")
	invite, err := ParseExternalInvite([]byte(strings.Replace(exchangeInvite, "SEQUENCE:2", "SEQUENCE:2\r\nLOCATION;LANGUAGE=ru-RU:ZOOM", 1)))
	if err != nil {
		t.Fatal(err)
	}
	in, start, end, err := invite.Times(almaty)
	if err != nil {
		t.Fatal(err)
	}
	if in.Timezone != "Asia/Qyzylorda" || in.Location != "ZOOM" || !start.Equal(time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)) || end.Sub(start) != 30*time.Minute {
		t.Fatalf("got %+v %v %v", in, start, end)
	}
	unknown := strings.ReplaceAll(exchangeInvite, "Qyzylorda Standard Time", "Custom Zone")
	invite, _ = ParseExternalInvite([]byte(unknown))
	if in, start, _, err = invite.Times(time.UTC); err != nil || in.Timezone != "Etc/GMT-5" || start.Hour() != 12 {
		t.Fatalf("offset fallback %+v %v %v", in, start, err)
	}
	utc := strings.ReplaceAll(strings.ReplaceAll(exchangeInvite, "DTSTART;TZID=Qyzylorda Standard Time:20261015T170000", "DTSTART:20261015T120000Z"), "DTEND;TZID=Qyzylorda Standard Time:20261015T173000", "")
	invite, _ = ParseExternalInvite([]byte(utc))
	if in, start, end, err = invite.Times(almaty); err != nil || start.Hour() != 12 || end.Sub(start) != time.Hour || in.Timezone != "Asia/Almaty" {
		t.Fatalf("utc %+v %v %v %v", in, start, end, err)
	}
	day := strings.ReplaceAll(strings.ReplaceAll(exchangeInvite, "DTSTART;TZID=Qyzylorda Standard Time:20261015T170000", "DTSTART;VALUE=DATE:20261015"), "DTEND;TZID=Qyzylorda Standard Time:20261015T173000", "DTEND;VALUE=DATE:20261016")
	invite, _ = ParseExternalInvite([]byte(day))
	if in, _, _, err = invite.Times(almaty); err != nil || !in.AllDay || in.Start != "2026-10-15" || in.End != "2026-10-16" {
		t.Fatalf("all day %+v %v", in, err)
	}
}

func TestExternalRecurringInvite(t *testing.T) {
	ics := strings.Replace(exchangeInvite, "SEQUENCE:2\r\n", "SEQUENCE:2\r\nRRULE:FREQ=WEEKLY;UNTIL=20261231T120000Z;BYDAY=TH\r\nEXDATE;TZID=Qyzylorda Standard Time:20261022T170000,20261029T170000\r\n", 1)
	invite, err := ParseExternalInvite([]byte(ics))
	if err != nil {
		t.Fatal(err)
	}
	in, _, _, err := invite.Times(time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if in.RRule != "FREQ=WEEKLY;UNTIL=20261231;BYDAY=TH" || strings.Join(in.Exdates, ",") != "2026-10-22,2026-10-29" {
		t.Fatalf("rule %q exdates %v", in.RRule, in.Exdates)
	}
	for _, bad := range []string{"RRULE:FREQ=MONTHLY;BYDAY=2TU\r\n", "RECURRENCE-ID:20261022T170000\r\n", "RDATE:20261023T170000\r\n"} {
		if _, err := ParseExternalInvite([]byte(strings.Replace(exchangeInvite, "SEQUENCE:2\r\n", "SEQUENCE:2\r\n"+bad, 1))); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestExternalSeriesWithChangedOccurrence(t *testing.T) {
	series := strings.Replace(exchangeInvite, "SEQUENCE:2\r\n", "SEQUENCE:2\r\nRRULE:FREQ=WEEKLY;COUNT=4\r\n", 1)
	instance := "BEGIN:VEVENT\r\nUID:040000008200E0\r\nRECURRENCE-ID;TZID=Qyzylorda Standard Time:20261022T170000\r\nSUMMARY:Перенесено\r\n" +
		"DTSTART;TZID=Qyzylorda Standard Time:20261023T090000\r\nDTEND;TZID=Qyzylorda Standard Time:20261023T100000\r\nORGANIZER:MAILTO:Organizer@Bank.test\r\nSEQUENCE:2\r\nEND:VEVENT\r\n"
	invite, err := ParseExternalInvite([]byte(strings.Replace(series, "END:VCALENDAR", instance+"END:VCALENDAR", 1)))
	if err != nil {
		t.Fatal(err)
	}
	almaty, _ := time.LoadLocation("Asia/Almaty")
	in, _, _, err := invite.Times(almaty)
	if err != nil {
		t.Fatal(err)
	}
	if in.Overrides == nil || len(*in.Overrides) != 1 {
		t.Fatalf("overrides: %+v", in.Overrides)
	}
	o := (*in.Overrides)[0]
	if o.Occurrence != "2026-10-22" || o.Title != "Перенесено" || o.Start != "2026-10-23T09:00" || o.StartAt.Format(time.RFC3339) != "2026-10-23T04:00:00Z" {
		t.Fatalf("override: %+v", o)
	}
	// A changed occurrence alone is applied on delivery but not answered here.
	alone := strings.Replace(exchangeInvite, "BEGIN:VEVENT\r\n"+exchangeInvite[strings.Index(exchangeInvite, "ORGANIZER"):strings.Index(exchangeInvite, "END:VCALENDAR")], instance, 1)
	if _, err := ParseExternalInvite([]byte(alone)); err == nil {
		t.Fatal("lone occurrence answerable")
	}
	if one, err := ParseITIP([]byte(alone)); err != nil || one.recurrenceID.value == "" {
		t.Fatalf("lone occurrence: %v %+v", err, one.recurrenceID)
	}
}
