package calendar

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const wallLayout = "2006-01-02T15:04"

func exdateSet(e Event) map[string]bool {
	out := make(map[string]bool, len(e.Exdates))
	for _, d := range e.Exdates {
		out[d] = true
	}
	return out
}

// seriesBase is the first occurrence's start as wall time in the event zone
// (all-day series run in UTC dates) and the length of one occurrence.
func seriesBase(e Event) (time.Time, time.Duration, bool) {
	if e.AllDay {
		a, err1 := time.Parse("2006-01-02", e.Start)
		b, err2 := time.Parse("2006-01-02", e.End)
		return a, b.Sub(a), err1 == nil && err2 == nil
	}
	loc, err := Zone(e.Timezone)
	if err != nil || e.StartAt == nil || e.EndAt == nil {
		return time.Time{}, 0, false
	}
	return e.StartAt.In(loc), e.EndAt.Sub(*e.StartAt), true
}

// expand returns the occurrences of a repeating event that intersect the
// range: [from,to) instants for timed events, [fromDate,toDate) for all-day.
func expand(e Event, from, to time.Time, fromDate, toDate string) []Event {
	rule, err := ParseRule(e.RRule)
	base, length, ok := seriesBase(e)
	if err != nil || !ok {
		return nil
	}
	skip := exdateSet(e)
	var out []Event
	rule.Starts(base, func(t time.Time) bool {
		day := t.Format("2006-01-02")
		c := e
		c.Occurrence, c.SeriesStart, c.SeriesEnd = day, e.Start, e.End
		c.seriesAt, c.seriesEndAt = e.StartAt, e.EndAt
		if e.AllDay {
			if day >= toDate {
				return false
			}
			last := t.Add(length).Format("2006-01-02")
			if last <= fromDate || skip[day] {
				return true
			}
			c.Start, c.End = day, last
		} else {
			if !t.Before(to) {
				return false
			}
			a, b := t.UTC(), t.Add(length).UTC()
			if !b.After(from) || skip[day] {
				return true
			}
			c.StartAt, c.EndAt = &a, &b
			c.Start, c.End = t.Format(wallLayout), t.Add(length).In(t.Location()).Format(wallLayout)
		}
		out = append(out, c)
		return true
	})
	return out
}

// seriesEnd is stored as series_until: when the final occurrence ends, or nil.
func seriesEnd(in Input, start, end time.Time) any {
	if in.RRule == "" {
		return nil
	}
	rule, err := ParseRule(in.RRule)
	if err != nil {
		return nil
	}
	base := start
	if !in.AllDay {
		if loc, err := Zone(in.Timezone); err == nil {
			base = start.In(loc)
		}
	}
	last := rule.LastEnd(base, end.Sub(start))
	if last == nil {
		return nil
	}
	return *last
}

// reminderFor is when to remind about the occurrence starting at t: minutes
// before it, or before 09:00 of the day for all-day events.
func reminderFor(e Event, t time.Time) time.Time {
	if e.AllDay {
		loc, err := Zone(e.Timezone)
		if err != nil {
			loc = time.UTC
		}
		t = time.Date(t.Year(), t.Month(), t.Day(), 9, 0, 0, 0, loc)
	}
	return t.Add(-time.Duration(e.ReminderMinutes) * time.Minute)
}

// nextReminder finds the first reminder time after now, across a series.
func nextReminder(e Event, now time.Time) (time.Time, bool) {
	base, _, ok := seriesBase(e)
	if !ok {
		return time.Time{}, false
	}
	if e.RRule == "" {
		at := reminderFor(e, base)
		return at, at.After(now)
	}
	rule, err := ParseRule(e.RRule)
	if err != nil {
		return time.Time{}, false
	}
	skip := exdateSet(e)
	var found time.Time
	rule.Starts(base, func(t time.Time) bool {
		if at := reminderFor(e, t); at.After(now) && !skip[t.Format("2006-01-02")] {
			found = at
			return false
		}
		return true
	})
	return found, !found.IsZero()
}

// addReminder keys reminder jobs by their time, so each occurrence of a
// series gets its own job under one event version.
func (s *Store) addReminder(ctx context.Context, tx pgx.Tx, e Event, at time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO calendar_jobs(event_id,event_version,kind,recipient,due_at,sequence,response_version) VALUES($1,$2,'reminder',$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
		e.ID, e.Version, e.Organizer, at, e.Sequence, int(at.Unix()/60))
	return err
}

// atOccurrence moves a series to the occurrence its reminder at `at` is for.
func atOccurrence(e Event, at time.Time) Event {
	if e.RRule == "" {
		return e
	}
	base, length, ok := seriesBase(e)
	if !ok {
		return e
	}
	rule, err := ParseRule(e.RRule)
	if err != nil {
		return e
	}
	out := e
	rule.Starts(base, func(t time.Time) bool {
		if !reminderFor(e, t).Equal(at) {
			return reminderFor(e, t).Before(at)
		}
		if e.AllDay {
			out.Start, out.End = t.Format("2006-01-02"), t.Add(length).Format("2006-01-02")
		} else {
			a, b := t.UTC(), t.Add(length).UTC()
			out.StartAt, out.EndAt = &a, &b
		}
		return false
	})
	return out
}

// recurrenceLines renders RRULE and EXDATE for an ICS VEVENT whose DTSTART
// is the series start (UTC DATE-TIME, or DATE for all-day events).
func recurrenceLines(e Event) []string {
	if e.RRule == "" {
		return nil
	}
	rule, err := ParseRule(e.RRule)
	base, _, ok := seriesBase(e)
	if err != nil || !ok {
		return nil
	}
	if e.seriesAt != nil {
		loc, _ := Zone(e.Timezone)
		base = e.seriesAt.In(loc)
	} else if e.SeriesStart != "" && e.AllDay {
		base, _ = time.Parse("2006-01-02", e.SeriesStart)
	}
	until := ""
	if rule.Until != "" {
		if e.AllDay {
			until = strings.ReplaceAll(rule.Until, "-", "")
		} else {
			d, _ := time.Parse("2006-01-02", rule.Until)
			until = time.Date(d.Year(), d.Month(), d.Day(), 23, 59, 59, 0, base.Location()).UTC().Format("20060102T150405Z")
		}
	}
	lines := []string{"RRULE:" + rule.String(until)}
	for _, d := range e.Exdates {
		day, err := time.Parse("2006-01-02", d)
		if err != nil {
			continue
		}
		if e.AllDay {
			lines = append(lines, "EXDATE;VALUE=DATE:"+day.Format("20060102"))
		} else {
			h, m, sec := base.Clock()
			lines = append(lines, "EXDATE:"+time.Date(day.Year(), day.Month(), day.Day(), h, m, sec, 0, base.Location()).UTC().Format("20060102T150405Z"))
		}
	}
	return lines
}
