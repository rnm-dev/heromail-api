package inbound

import (
	"bytes"
	"strings"
)

// CalendarPreview is display-only. An incoming ICS part is untrusted mail;
// viewing it never creates an event or sends a reply.
type CalendarPreview struct {
	Method      string `json:"method"`
	UID         string `json:"uid"`
	Title       string `json:"title"`
	Start       string `json:"start"`
	End         string `json:"end"`
	Organizer   string `json:"organizer"`
	Unsupported bool   `json:"unsupported"`
}

func parseCalendarPreview(data []byte) *CalendarPreview {
	if len(data) == 0 || len(data) > 64<<10 || bytes.IndexByte(data, 0) >= 0 {
		return nil
	}
	raw := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n")
	physical := strings.Split(raw, "\n")
	if len(physical) > 1024 {
		return nil
	}
	lines := make([]string, 0, len(physical))
	for _, line := range physical {
		if len(line) > 8192 {
			return nil
		}
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') && len(lines) > 0 {
			lines[len(lines)-1] += line[1:]
		} else {
			lines = append(lines, line)
		}
	}
	out := &CalendarPreview{}
	inside := false
	events := 0
	for _, line := range lines {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		property := strings.ToUpper(strings.SplitN(name, ";", 2)[0])
		switch property {
		case "BEGIN":
			if value == "VEVENT" {
				inside = true
				events++
			}
		case "END":
			if value == "VEVENT" {
				inside = false
			}
		case "METHOD":
			if !inside {
				out.Method = strings.ToUpper(value)
			}
		case "UID":
			if inside {
				out.UID = value
			}
		case "SUMMARY":
			if inside {
				out.Title = icsUnescape(value)
			}
		case "DTSTART":
			if inside {
				out.Start = value
			}
		case "DTEND":
			if inside {
				out.End = value
			}
		case "ORGANIZER":
			if inside {
				out.Organizer = value
				if len(value) >= 7 && strings.EqualFold(value[:7], "mailto:") {
					out.Organizer = value[7:]
				}
			}
		case "RRULE", "RDATE", "EXDATE", "RECURRENCE-ID":
			if inside {
				out.Unsupported = true
			}
		}
	}
	if events != 1 || out.UID == "" || out.Title == "" || out.Start == "" || out.End == "" {
		return nil
	}
	if out.Method != "REQUEST" && out.Method != "CANCEL" {
		out.Unsupported = true
	}
	return out
}

func icsUnescape(value string) string {
	value = strings.ReplaceAll(value, "\\n", "\n")
	value = strings.ReplaceAll(value, "\\N", "\n")
	value = strings.ReplaceAll(value, "\\,", ",")
	value = strings.ReplaceAll(value, "\\;", ";")
	return strings.ReplaceAll(value, "\\\\", "\\")
}
