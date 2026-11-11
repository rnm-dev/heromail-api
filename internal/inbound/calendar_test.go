package inbound

import (
	"strings"
	"testing"
)

func TestCalendarPreviewAndICSDownload(t *testing.T) {
	raw := []byte("From: host@example.test\r\nTo: guest@example.test\r\nSubject: Meeting\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=cal\r\n\r\n--cal\r\nContent-Type: text/plain\r\n\r\nInvitation\r\n--cal\r\nContent-Type: text/calendar; method=REQUEST; charset=UTF-8\r\n\r\nBEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:abc@example.test\r\nSUMMARY:Planning\r\nDTSTART:20261020T090000Z\r\nDTEND:20261020T100000Z\r\nORGANIZER:mailto:host@example.test\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n--cal--\r\n")
	p := Present(raw)
	if p.Calendar == nil || p.Calendar.Title != "Planning" || p.Calendar.UID != "abc@example.test" || p.Calendar.Unsupported {
		t.Fatalf("preview: %+v", p.Calendar)
	}
	if len(p.Attachments) != 1 || p.Attachments[0].Filename != "invitation.ics" {
		t.Fatalf("attachments: %+v", p.Attachments)
	}
	_, data, incomplete := ScanAttachments(raw, p.Attachments[0].ID)
	if incomplete || !strings.Contains(string(data), "UID:abc@example.test") {
		t.Fatalf("download: %q incomplete=%v", data, incomplete)
	}
	repeating := strings.Replace(string(raw), "END:VEVENT", "RRULE:FREQ=MONTHLY;BYDAY=2TU\r\nEND:VEVENT", 1)
	if got := Present([]byte(repeating)).Calendar; got == nil || !got.Unsupported {
		t.Fatalf("recurrence supported silently: %+v", got)
	}
}
