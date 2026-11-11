package calendar

import (
	"fmt"
	"strings"
)

func icsEscape(value string) string {
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	value = strings.ReplaceAll(value, "\n", "\\n")
	value = strings.ReplaceAll(value, ";", "\\;")
	return strings.ReplaceAll(value, ",", "\\,")
}

// foldICS observes the iCalendar 75-octet line limit without splitting a
// UTF-8 codepoint. Continuation lines begin with one space.
func foldICS(line string) string {
	var out strings.Builder
	count := 0
	for _, r := range line {
		width := len(string(r))
		if count+width > 75 {
			out.WriteString("\r\n ")
			count = 1
		}
		out.WriteRune(r)
		count += width
	}
	return out.String()
}

func buildICS(e Event, method, recipient, response string) string {
	stamp := e.UpdatedAt.UTC().Format("20060102T150405Z")
	lines := []string{
		"BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Heromail//Calendar MVP//EN",
		"CALSCALE:GREGORIAN", "METHOD:" + method, "BEGIN:VEVENT",
		"UID:" + e.UID, "DTSTAMP:" + stamp,
		fmt.Sprintf("SEQUENCE:%d", e.Sequence),
		"SUMMARY:" + icsEscape(e.Title),
		"DESCRIPTION:" + icsEscape(e.Description),
		"LOCATION:" + icsEscape(e.Location),
		"ORGANIZER:mailto:" + e.Organizer,
	}
	if method == "REPLY" {
		lines = append(lines, "ATTENDEE;PARTSTAT="+strings.ToUpper(response)+":mailto:"+recipient)
	} else {
		// Everyone invited is listed, as other clients do; the recipient is
		// the one asked to answer.
		listed := false
		for _, a := range e.Responses {
			if a.Email == recipient {
				listed = true
				lines = append(lines, "ATTENDEE;RSVP=TRUE;PARTSTAT="+strings.ToUpper(strings.ReplaceAll(a.Response, "_", "-"))+":mailto:"+a.Email)
			} else {
				lines = append(lines, "ATTENDEE;PARTSTAT="+strings.ToUpper(strings.ReplaceAll(a.Response, "_", "-"))+":mailto:"+a.Email)
			}
		}
		if !listed {
			lines = append(lines, "ATTENDEE;RSVP=TRUE:mailto:"+recipient)
		}
	}
	if e.AllDay {
		lines = append(lines, "DTSTART;VALUE=DATE:"+strings.ReplaceAll(e.Start, "-", ""), "DTEND;VALUE=DATE:"+strings.ReplaceAll(e.End, "-", ""))
	} else {
		lines = append(lines, "DTSTART:"+e.StartAt.UTC().Format("20060102T150405Z"), "DTEND:"+e.EndAt.UTC().Format("20060102T150405Z"))
	}
	if method == "CANCEL" {
		lines = append(lines, "STATUS:CANCELLED")
	}
	lines = append(lines, "END:VEVENT", "END:VCALENDAR")
	for i := range lines {
		lines[i] = foldICS(lines[i])
	}
	return strings.Join(lines, "\r\n") + "\r\n"
}
