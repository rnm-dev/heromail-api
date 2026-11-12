package calendar

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// windowsZones maps Exchange/Outlook time zone names that have no IANA
// equivalent by name. Anything else falls back to the VTIMEZONE offset.
var windowsZones = map[string]string{
	"Qyzylorda Standard Time":      "Asia/Qyzylorda",
	"Central Asia Standard Time":   "Asia/Almaty",
	"West Asia Standard Time":      "Asia/Tashkent",
	"Ekaterinburg Standard Time":   "Asia/Yekaterinburg",
	"Russian Standard Time":        "Europe/Moscow",
	"UTC":                          "UTC",
	"GMT Standard Time":            "Europe/London",
	"W. Europe Standard Time":      "Europe/Berlin",
	"Central Europe Standard Time": "Europe/Budapest",
	"FLE Standard Time":            "Europe/Kiev",
	"Turkey Standard Time":         "Europe/Istanbul",
	"Arabian Standard Time":        "Asia/Dubai",
	"China Standard Time":          "Asia/Shanghai",
	"Singapore Standard Time":      "Asia/Singapore",
	"Tokyo Standard Time":          "Asia/Tokyo",
	"Eastern Standard Time":        "America/New_York",
	"Central Standard Time":        "America/Chicago",
	"Pacific Standard Time":        "America/Los_Angeles",
}

func paramValue(params, name string) string {
	for _, part := range strings.Split(params, ";") {
		k, v, ok := strings.Cut(part, "=")
		if ok && strings.EqualFold(k, name) {
			return strings.Trim(v, "\"")
		}
	}
	return ""
}

// zoneFor resolves a TZID to an IANA location: by name, through the Windows
// table, or as a whole-hour Etc/GMT zone from the VTIMEZONE STANDARD offset.
func (e ExternalInvite) zoneFor(tzid string, fallback *time.Location) (*time.Location, string) {
	if tzid == "" {
		return fallback, fallback.String()
	}
	for _, name := range []string{tzid, windowsZones[tzid]} {
		if name == "" || name == "Local" {
			continue
		}
		if loc, err := time.LoadLocation(name); err == nil {
			return loc, name
		}
	}
	current, standard := "", false
	for _, line := range e.timezones {
		p, ok := parseProperty(line)
		if !ok {
			continue
		}
		switch {
		case p.name == "TZID":
			current = p.value
		case p.name == "BEGIN":
			standard = strings.EqualFold(p.value, "STANDARD")
		case p.name == "TZOFFSETTO" && standard && current == tzid:
			v := strings.TrimSpace(p.value)
			if len(v) >= 5 && v[3:5] == "00" {
				if h, err := strconv.Atoi(v[:3]); err == nil && h >= -12 && h <= 14 {
					name := "UTC"
					if h != 0 {
						// Etc/GMT signs are inverted by POSIX convention.
						name = fmt.Sprintf("Etc/GMT%+d", -h)
					}
					if loc, err := time.LoadLocation(name); err == nil {
						return loc, name
					}
				}
			}
		}
	}
	return fallback, fallback.String()
}

// Times turns DTSTART/DTEND into an Event interval. Floating times use the
// recipient's calendar zone; a missing DTEND follows RFC 5545 defaults.
func (e ExternalInvite) Times(fallback *time.Location) (in Input, start, end time.Time, err error) {
	bad := invalid("Не удалось прочитать время встречи")
	sv := strings.TrimSpace(e.startProp.value)
	ev := strings.TrimSpace(e.endProp.value)
	if strings.EqualFold(paramValue(e.startProp.params, "VALUE"), "DATE") || len(sv) == 8 {
		in.AllDay = true
		if start, err = time.Parse("20060102", sv); err != nil {
			return in, start, end, bad
		}
		end = start.AddDate(0, 0, 1)
		if ev != "" {
			if end, err = time.Parse("20060102", ev); err != nil {
				return in, start, end, bad
			}
		}
		in.Timezone = fallback.String()
		in.Start, in.End = start.Format("2006-01-02"), end.Format("2006-01-02")
		for _, p := range e.exdates {
			for _, v := range strings.Split(p.value, ",") {
				if v = strings.TrimSpace(v); len(v) >= 8 {
					if d, err := time.Parse("20060102", v[:8]); err == nil {
						in.Exdates = append(in.Exdates, d.Format("2006-01-02"))
					}
				}
			}
		}
	} else {
		parse := func(p property) (time.Time, string, error) {
			v := strings.TrimSpace(p.value)
			if strings.HasSuffix(v, "Z") {
				t, err := time.Parse("20060102T150405Z", v)
				return t, "", err
			}
			loc, name := e.zoneFor(paramValue(p.params, "TZID"), fallback)
			t, err := time.ParseInLocation("20060102T150405", v, loc)
			return t, name, err
		}
		var zone string
		if start, zone, err = parse(e.startProp); err != nil {
			return in, start, end, bad
		}
		loc, _ := e.zoneFor(paramValue(e.startProp.params, "TZID"), fallback)
		for _, p := range e.exdates {
			for _, v := range strings.Split(p.value, ",") {
				if t, _, err := parse(property{params: p.params, value: v}); err == nil {
					in.Exdates = append(in.Exdates, t.In(loc).Format("2006-01-02"))
				}
			}
		}
		end = start.Add(time.Hour)
		if ev != "" {
			if end, _, err = parse(e.endProp); err != nil {
				return in, start, end, bad
			}
		}
		if zone == "" {
			zone = fallback.String()
		}
		in.Timezone = zone
		start, end = start.UTC(), end.UTC()
	}
	if !end.After(start) || end.Sub(start) > 366*24*time.Hour {
		return in, start, end, bad
	}
	in.Title = strings.TrimSpace(e.Title)
	if in.Title == "" {
		in.Title = "Встреча"
	}
	in.Title = truncateRunes(in.Title, 200)
	in.Description = truncateRunes(e.Description, 20000)
	in.Location = truncateRunes(e.Location, 2000)
	in.Organizer = e.Organizer
	if e.rrule != "" {
		rule, err := ParseRule(e.rrule)
		if err != nil {
			return in, start, end, bad
		}
		in.RRule = rule.String(strings.ReplaceAll(rule.Until, "-", ""))
	}
	if in.Exdates == nil || in.RRule == "" {
		in.Exdates = []string{}
	}
	overrides := []Override{}
	if in.RRule != "" {
		for _, inst := range e.instances {
			if o, ok := inst.Override(in, fallback); ok && len(overrides) < 200 {
				overrides = append(overrides, o)
			}
		}
	}
	in.Overrides = &overrides
	return in, start, end, nil
}

// Occurrence is the original date (in the series zone) a changed occurrence
// replaces, from its RECURRENCE-ID.
func (e ExternalInvite) Occurrence(series Input, fallback *time.Location) (string, bool) {
	v := strings.TrimSpace(e.recurrenceID.value)
	if len(v) < 8 {
		return "", false
	}
	if series.AllDay || len(v) == 8 {
		d, err := time.Parse("20060102", v[:8])
		return d.Format("2006-01-02"), err == nil
	}
	var t time.Time
	var err error
	if strings.HasSuffix(v, "Z") {
		t, err = time.Parse("20060102T150405Z", v)
	} else {
		loc, _ := e.zoneFor(paramValue(e.recurrenceID.params, "TZID"), fallback)
		t, err = time.ParseInLocation("20060102T150405", v, loc)
	}
	loc, zerr := Zone(series.Timezone)
	if err != nil || zerr != nil {
		return "", false
	}
	return t.In(loc).Format("2006-01-02"), true
}

// Override converts a changed occurrence into an override of the series.
func (e ExternalInvite) Override(series Input, fallback *time.Location) (Override, bool) {
	day, ok := e.Occurrence(series, fallback)
	if !ok {
		return Override{}, false
	}
	in, start, end, err := e.Times(fallback)
	if err != nil || in.AllDay != series.AllDay {
		return Override{}, false
	}
	o := Override{Occurrence: day, Title: in.Title, Location: in.Location, Description: in.Description}
	if in.AllDay {
		o.Start, o.End = in.Start, in.End
	} else {
		loc, err := Zone(series.Timezone)
		if err != nil {
			return Override{}, false
		}
		a, b := start.UTC(), end.UTC()
		o.Start, o.End, o.StartAt, o.EndAt = a.In(loc).Format(wallLayout), b.In(loc).Format(wallLayout), &a, &b
	}
	return o, true
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// SaveExternal records the user's answer in their own calendar. Accepted and
// tentative answers upsert a read-only copy; declined removes it. An older
// SEQUENCE never overwrites a newer copy.
func (s *Store) SaveExternal(ctx context.Context, ws, user, messageID, attendee, response string, invite ExternalInvite) error {
	cal, err := s.ensure(ctx, ws, user)
	if err != nil {
		return err
	}
	if response == "declined" {
		_, err = s.pool.Exec(ctx, `DELETE FROM calendar_external_events WHERE calendar_id=$1 AND uid=$2`, cal, invite.UID)
		return err
	}
	var zone string
	if err = s.pool.QueryRow(ctx, `SELECT timezone FROM calendars WHERE id=$1`, cal).Scan(&zone); err != nil {
		return err
	}
	fallback, err := Zone(zone)
	if err != nil {
		fallback = time.UTC
	}
	in, start, end, err := invite.Times(fallback)
	if err != nil {
		return err
	}
	seq, _ := strconv.Atoi(invite.Sequence)
	until := seriesEnd(in, start, end)
	var startAt, endAt, startDate, endDate any
	if in.AllDay {
		startDate, endDate = in.Start, in.End
	} else {
		startAt, endAt = start, end
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO calendar_external_events(calendar_id,uid,sequence,message_id,attendee,response,organizer_email,title,description,location,timezone,all_day,start_at,end_at,start_date,end_date,rrule,exdates,series_until,overrides)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::date,$16::date,$17,$18,$19,$20)
		ON CONFLICT(calendar_id,uid) DO UPDATE SET sequence=EXCLUDED.sequence,message_id=EXCLUDED.message_id,attendee=EXCLUDED.attendee,response=EXCLUDED.response,
		organizer_email=EXCLUDED.organizer_email,title=EXCLUDED.title,description=EXCLUDED.description,location=EXCLUDED.location,timezone=EXCLUDED.timezone,
		all_day=EXCLUDED.all_day,start_at=EXCLUDED.start_at,end_at=EXCLUDED.end_at,start_date=EXCLUDED.start_date,end_date=EXCLUDED.end_date,rrule=EXCLUDED.rrule,exdates=EXCLUDED.exdates,series_until=EXCLUDED.series_until,overrides=EXCLUDED.overrides,updated_at=now()
		WHERE calendar_external_events.sequence<=EXCLUDED.sequence`,
		cal, invite.UID, seq, messageID, strings.ToLower(attendee), response, in.Organizer, in.Title, in.Description, in.Location, in.Timezone, in.AllDay, startAt, endAt, startDate, endDate, in.RRule, in.Exdates, until, encodeOverrides(in))
	return err
}
