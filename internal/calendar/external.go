package calendar

import (
	"bytes"
	"context"
	"errors"
	"net/mail"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// ExternalInvite is a REQUEST received by mail from any organizer. It is
// untrusted input: answering mails a REPLY from the receiving mailbox and keeps
// a private read-only copy in the answering user's calendar (SaveExternal).
type ExternalInvite struct {
	UID, Sequence, Title, Organizer string
	Description, Location           string
	Attendees                       []string
	timezones                       []string
	start, end, summary, organizer  string
	startProp, endProp              property
}

type property struct{ name, params, value, line string }

// parseProperty splits a content line, honoring quoted parameter values that
// may themselves contain ':' or ';'.
func parseProperty(line string) (property, bool) {
	quoted := false
	for i, r := range line {
		switch {
		case r == '"':
			quoted = !quoted
		case r == ':' && !quoted:
			head := line[:i]
			name, params, _ := strings.Cut(head, ";")
			return property{strings.ToUpper(name), params, line[i+1:], line}, true
		}
	}
	return property{}, false
}

func mailtoAddress(value string) string {
	value = strings.TrimSpace(value)
	if len(value) >= 7 && strings.EqualFold(value[:7], "mailto:") {
		value = value[7:]
	}
	addr, err := mail.ParseAddress(value)
	if err != nil || addr.Address != value {
		return ""
	}
	return strings.ToLower(value)
}

// ParseExternalInvite accepts one non-recurring VEVENT with METHOD:REQUEST.
// Other shapes stay download-only rather than answering a single instance.
func ParseExternalInvite(data []byte) (ExternalInvite, error) {
	unsupported := invalid("Это приглашение нельзя подтвердить из Heromail. Скачайте ICS-файл.")
	if len(data) == 0 || len(data) > 64<<10 || bytes.IndexByte(data, 0) >= 0 {
		return ExternalInvite{}, unsupported
	}
	raw := strings.ReplaceAll(strings.ReplaceAll(string(data), "\r\n", "\n"), "\r", "\n")
	physical := strings.Split(raw, "\n")
	if len(physical) > 1024 {
		return ExternalInvite{}, unsupported
	}
	lines := make([]string, 0, len(physical))
	for _, line := range physical {
		if len(line) > 8192 {
			return ExternalInvite{}, unsupported
		}
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') && len(lines) > 0 {
			lines[len(lines)-1] += line[1:]
		} else if line != "" {
			lines = append(lines, line)
		}
	}
	var out ExternalInvite
	var method string
	var stack []string
	var zone []string
	events := 0
	for _, line := range lines {
		p, ok := parseProperty(line)
		if !ok {
			continue
		}
		value := strings.ToUpper(strings.TrimSpace(p.value))
		if p.name == "BEGIN" {
			stack = append(stack, value)
			if len(stack) > 8 {
				return ExternalInvite{}, unsupported
			}
			if value == "VEVENT" {
				events++
			}
		}
		top := ""
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		inTimezone := len(stack) >= 2 && stack[1] == "VTIMEZONE"
		if inTimezone {
			zone = append(zone, line)
		}
		if p.name == "END" {
			if len(stack) == 0 || stack[len(stack)-1] != value {
				return ExternalInvite{}, unsupported
			}
			stack = stack[:len(stack)-1]
			if value == "VTIMEZONE" {
				out.timezones = append(out.timezones, zone...)
				zone = nil
			}
			continue
		}
		if p.name == "METHOD" && len(stack) == 1 {
			method = value
		}
		if top != "VEVENT" {
			continue
		}
		switch p.name {
		case "UID":
			out.UID = p.value
		case "SEQUENCE":
			out.Sequence = strings.TrimSpace(p.value)
		case "SUMMARY":
			out.Title, out.summary = icsUnescape(p.value), line
		case "DTSTART":
			out.start, out.startProp = line, p
		case "DTEND":
			out.end, out.endProp = line, p
		case "LOCATION":
			out.Location = icsUnescape(p.value)
		case "DESCRIPTION":
			out.Description = icsUnescape(p.value)
		case "ORGANIZER":
			out.Organizer, out.organizer = mailtoAddress(p.value), line
		case "ATTENDEE":
			if addr := mailtoAddress(p.value); addr != "" {
				out.Attendees = append(out.Attendees, addr)
			}
		case "RRULE", "RDATE", "EXDATE", "RECURRENCE-ID":
			return ExternalInvite{}, unsupported
		}
	}
	if method != "REQUEST" || events != 1 || len(stack) != 0 || out.UID == "" || out.Organizer == "" || out.start == "" || len(out.timezones) > 400 {
		return ExternalInvite{}, unsupported
	}
	if out.Sequence == "" {
		out.Sequence = "0"
	}
	return out, nil
}

func icsUnescape(value string) string {
	value = strings.ReplaceAll(value, "\\n", "\n")
	value = strings.ReplaceAll(value, "\\N", "\n")
	value = strings.ReplaceAll(value, "\\,", ",")
	value = strings.ReplaceAll(value, "\\;", ";")
	return strings.ReplaceAll(value, "\\\\", "\\")
}

// Invites reports whether address may answer as an attendee.
func (e ExternalInvite) Invites(address string) bool {
	address = strings.ToLower(address)
	for _, a := range e.Attendees {
		if a == address {
			return true
		}
	}
	return false
}

var partstat = map[string]string{"accepted": "ACCEPTED", "tentative": "TENTATIVE", "declined": "DECLINED"}

// Reply builds an iTIP REPLY (RFC 5546 §3.2.3) for one attendee, echoing the
// organizer's UID, SEQUENCE, times and their time zone definitions.
func (e ExternalInvite) Reply(attendee, response string, now time.Time) (string, error) {
	status, ok := partstat[response]
	if !ok {
		return "", invalid("Выберите «Да», «Возможно» или «Нет»")
	}
	if !e.Invites(attendee) {
		return "", invalid("Приглашение адресовано другому почтовому ящику")
	}
	lines := []string{"BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Heromail//Calendar//EN", "METHOD:REPLY"}
	lines = append(lines, e.timezones...)
	lines = append(lines, "BEGIN:VEVENT", "UID:"+e.UID, "SEQUENCE:"+e.Sequence,
		"DTSTAMP:"+now.UTC().Format("20060102T150405Z"), e.organizer,
		"ATTENDEE;PARTSTAT="+status+":mailto:"+strings.ToLower(attendee), e.start)
	for _, line := range []string{e.end, e.summary} {
		if line != "" {
			lines = append(lines, line)
		}
	}
	lines = append(lines, "END:VEVENT", "END:VCALENDAR")
	for i := range lines {
		lines[i] = foldICS(lines[i])
	}
	return strings.Join(lines, "\r\n") + "\r\n", nil
}

// ExternalReply is the latest answer chosen for one received message.
type ExternalReply struct {
	Response string
	Revision int
	Stamp    time.Time
	EmailID  *string
}

// Sent reports whether the REPLY reached the outbound queue.
func (r ExternalReply) Sent() bool { return r.EmailID != nil }

func (s *Store) ExternalReply(ctx context.Context, messageID string) (ExternalReply, error) {
	var out ExternalReply
	err := s.pool.QueryRow(ctx, `SELECT response,revision,stamp,email_id::text FROM calendar_external_replies WHERE message_id=$1`, messageID).Scan(&out.Response, &out.Revision, &out.Stamp, &out.EmailID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ExternalReply{}, nil
	}
	return out, err
}

// BeginExternalReply records a new choice before it is mailed. It fails with
// ErrConflict when another request changed the answer since prev was read.
func (s *Store) BeginExternalReply(ctx context.Context, messageID, attendee, response string, prev int) (ExternalReply, error) {
	out := ExternalReply{Response: response}
	err := s.pool.QueryRow(ctx, `INSERT INTO calendar_external_replies(message_id,attendee,response,revision,stamp) VALUES($1,$2,$3,$4+1,date_trunc('second',now()))
		ON CONFLICT(message_id) DO UPDATE SET attendee=EXCLUDED.attendee,response=EXCLUDED.response,revision=EXCLUDED.revision,stamp=EXCLUDED.stamp,email_id=NULL,updated_at=now()
		WHERE calendar_external_replies.revision=$4 RETURNING revision,stamp`, messageID, attendee, response, prev).Scan(&out.Revision, &out.Stamp)
	if errors.Is(err, pgx.ErrNoRows) {
		return ExternalReply{}, ErrConflict
	}
	return out, err
}

func (s *Store) FinishExternalReply(ctx context.Context, messageID string, revision int, emailID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE calendar_external_replies SET email_id=$3,updated_at=now() WHERE message_id=$1 AND revision=$2`, messageID, revision, emailID)
	return err
}
