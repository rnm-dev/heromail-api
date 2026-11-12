package calendar

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Override replaces one occurrence of a series, identified by its original
// date in the event zone. Start/End are wall times (dates for all-day series);
// StartAt/EndAt are derived instants for timed series.
type Override struct {
	Occurrence  string     `json:"occurrence"`
	Title       string     `json:"title"`
	Location    string     `json:"location"`
	Description string     `json:"description"`
	Start       string     `json:"start"`
	End         string     `json:"end"`
	StartAt     *time.Time `json:"start_at,omitempty"`
	EndAt       *time.Time `json:"end_at,omitempty"`
}

func decodeOverrides(raw []byte, in *Input) error {
	list := []Override{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &list); err != nil {
			return err
		}
	}
	in.Overrides = &list
	return nil
}

func overrideList(in Input) []Override {
	if in.Overrides == nil {
		return []Override{}
	}
	return *in.Overrides
}

func encodeOverrides(in Input) []byte {
	raw, _ := json.Marshal(overrideList(in))
	return raw
}

// normalizeOverrides validates overrides against the series in `in` (already
// validated): times, sizes, and that each names a real, not skipped
// occurrence. Overrides for dates the rule no longer produces are dropped.
func normalizeOverrides(in *Input, start time.Time) error {
	list := overrideList(*in)
	if len(list) == 0 || in.RRule == "" {
		empty := []Override{}
		in.Overrides = &empty
		return nil
	}
	if len(list) > 200 {
		return invalid("Слишком много изменённых повторений")
	}
	rule, err := ParseRule(in.RRule)
	if err != nil {
		return err
	}
	loc, err := Zone(in.Timezone)
	if err != nil {
		return err
	}
	base := start
	if !in.AllDay {
		base = start.In(loc)
	}
	want := map[string]bool{}
	for _, o := range list {
		want[o.Occurrence] = true
	}
	real := map[string]bool{}
	last := ""
	for _, o := range list {
		if o.Occurrence > last {
			last = o.Occurrence
		}
	}
	rule.Starts(base, func(t time.Time) bool {
		day := t.Format("2006-01-02")
		if want[day] {
			real[day] = true
		}
		return day < last
	})
	skip := map[string]bool{}
	for _, d := range in.Exdates {
		skip[d] = true
	}
	out := make([]Override, 0, len(list))
	seen := map[string]bool{}
	for _, o := range list {
		if !real[o.Occurrence] || skip[o.Occurrence] || seen[o.Occurrence] {
			continue
		}
		seen[o.Occurrence] = true
		o.Title = strings.TrimSpace(o.Title)
		if o.Title == "" {
			o.Title = in.Title
		}
		if utf8.RuneCountInString(o.Title) > 200 || len(o.Description) > 20000 || len(o.Location) > 2000 {
			return invalid("Проверьте название, описание и место изменённого повторения")
		}
		var a, b time.Time
		if in.AllDay {
			a, err = time.Parse("2006-01-02", o.Start)
			if err == nil {
				b, err = time.Parse("2006-01-02", o.End)
			}
			o.StartAt, o.EndAt = nil, nil
		} else {
			a, err = Wall(o.Start, loc)
			if err == nil {
				b, err = Wall(o.End, loc)
			}
			ua, ub := a.UTC(), b.UTC()
			o.StartAt, o.EndAt = &ua, &ub
		}
		if err != nil || !b.After(a) || b.Sub(a) > 366*24*time.Hour {
			return invalid("Конец изменённого повторения должен быть позже начала")
		}
		out = append(out, o)
	}
	in.Overrides = &out
	return nil
}

func overrideMap(e Event) map[string]Override {
	out := map[string]Override{}
	for _, o := range overrideList(e.Input) {
		out[o.Occurrence] = o
	}
	return out
}

// applyOverride turns a series copy into the overridden occurrence.
func applyOverride(c *Event, o Override) {
	c.Title, c.Location, c.Description = o.Title, o.Location, o.Description
	c.Start, c.End = o.Start, o.End
	if !c.AllDay && o.StartAt != nil && o.EndAt != nil {
		a, b := *o.StartAt, *o.EndAt
		c.StartAt, c.EndAt = &a, &b
	}
	c.Overridden = true
}

// overrideStart is when an overridden occurrence begins, as wall time in loc.
func overrideStart(e Event, o Override, loc *time.Location) (time.Time, bool) {
	if e.AllDay {
		t, err := time.Parse("2006-01-02", o.Start)
		return t, err == nil
	}
	if o.StartAt == nil {
		return time.Time{}, false
	}
	return o.StartAt.In(loc), true
}

// overrideBlocks renders one VEVENT per override with RECURRENCE-ID naming the
// original occurrence; extra holds lines shared with the master (organizer,
// attendees).
func overrideBlocks(e Event, stamp, status string, extra []string) []string {
	var lines []string
	base, _, ok := seriesBase(e)
	if e.seriesAt != nil {
		loc, _ := Zone(e.Timezone)
		base = e.seriesAt.In(loc)
	}
	for _, o := range overrideList(e.Input) {
		day, err := time.Parse("2006-01-02", o.Occurrence)
		if err != nil || !ok {
			continue
		}
		lines = append(lines, "BEGIN:VEVENT", "UID:"+e.UID, "DTSTAMP:"+stamp, fmt.Sprintf("SEQUENCE:%d", e.Sequence))
		if e.AllDay {
			lines = append(lines, "RECURRENCE-ID;VALUE=DATE:"+day.Format("20060102"),
				"DTSTART;VALUE=DATE:"+strings.ReplaceAll(o.Start, "-", ""), "DTEND;VALUE=DATE:"+strings.ReplaceAll(o.End, "-", ""))
		} else if o.StartAt != nil && o.EndAt != nil {
			h, m, s := base.Clock()
			orig := time.Date(day.Year(), day.Month(), day.Day(), h, m, s, 0, base.Location()).UTC()
			lines = append(lines, "RECURRENCE-ID:"+orig.Format("20060102T150405Z"),
				"DTSTART:"+o.StartAt.UTC().Format("20060102T150405Z"), "DTEND:"+o.EndAt.UTC().Format("20060102T150405Z"))
		} else {
			lines = lines[:len(lines)-4]
			continue
		}
		lines = append(lines, "SUMMARY:"+icsEscape(o.Title))
		if o.Location != "" {
			lines = append(lines, "LOCATION:"+icsEscape(o.Location))
		}
		if o.Description != "" {
			lines = append(lines, "DESCRIPTION:"+icsEscape(o.Description))
		}
		lines = append(lines, extra...)
		if status != "" {
			lines = append(lines, "STATUS:"+status)
		}
		lines = append(lines, "END:VEVENT")
	}
	return lines
}
