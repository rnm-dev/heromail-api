package inbound

import (
	"bytes"
	"context"
	"log"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/rnm/heromail/backend/internal/calendar"
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
	if out.Method != "REQUEST" && out.Method != "CANCEL" && out.Method != "REPLY" {
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

// applyCalendar feeds a delivered iTIP part to the calendar inside a savepoint:
// a calendar failure is logged and never blocks delivery of the message.
func applyCalendar(ctx context.Context, tx pgx.Tx, p DeliverParams, from string) {
	pres := Present(p.Raw)
	if len(pres.CalendarICS) == 0 || from == "" {
		return
	}
	var address string
	if err := tx.QueryRow(ctx, `SELECT lower(m.local_part||'@'||d.domain) FROM mailboxes m JOIN domains d ON d.id=m.domain_id WHERE m.id=$1`, p.MailboxID).Scan(&address); err != nil {
		log.Printf("calendar on delivery: mailbox %s: %v", p.MailboxID, err)
		return
	}
	sp, err := tx.Begin(ctx)
	if err != nil {
		log.Printf("calendar on delivery: %v", err)
		return
	}
	if err = calendar.ApplyIncoming(ctx, sp, address, from, pres.CalendarICS); err != nil {
		log.Printf("calendar on delivery: %v", err)
		_ = sp.Rollback(ctx)
		return
	}
	if err = sp.Commit(ctx); err != nil {
		log.Printf("calendar on delivery: %v", err)
	}
}
