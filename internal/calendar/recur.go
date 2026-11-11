package calendar

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Rule is the supported RRULE subset: FREQ=DAILY|WEEKLY|MONTHLY|YEARLY with
// INTERVAL, COUNT or UNTIL (a calendar date, inclusive) and BYDAY for weekly.
// Monthly/yearly repeat the start's day; months without it are skipped (RFC 5545).
type Rule struct {
	Freq     string
	Interval int
	Count    int
	Until    string // YYYY-MM-DD in the event's zone, "" = no end date
	ByDay    []time.Weekday
}

var dayCodes = []string{"SU", "MO", "TU", "WE", "TH", "FR", "SA"}

// maxOccurrences bounds expansion work for any one series and request.
const maxOccurrences = 20000

func ParseRule(value string) (Rule, error) {
	bad := invalid("Неподдерживаемое правило повторения")
	r := Rule{Interval: 1}
	value = strings.TrimPrefix(strings.TrimSpace(value), "RRULE:")
	if value == "" || len(value) > 200 {
		return r, bad
	}
	for _, part := range strings.Split(value, ";") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return r, bad
		}
		switch strings.ToUpper(k) {
		case "FREQ":
			r.Freq = strings.ToUpper(v)
		case "INTERVAL":
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 999 {
				return r, bad
			}
			r.Interval = n
		case "COUNT":
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 1000 {
				return r, bad
			}
			r.Count = n
		case "UNTIL":
			if len(v) < 8 {
				return r, bad
			}
			d, err := time.Parse("20060102", v[:8])
			if err != nil {
				return r, bad
			}
			r.Until = d.Format("2006-01-02")
		case "BYDAY":
			for _, code := range strings.Split(strings.ToUpper(v), ",") {
				i := indexOf(dayCodes, code)
				if i < 0 {
					return r, bad
				}
				r.ByDay = append(r.ByDay, time.Weekday(i))
			}
		case "WKST":
		default:
			return r, bad
		}
	}
	if indexOf([]string{"DAILY", "WEEKLY", "MONTHLY", "YEARLY"}, r.Freq) < 0 || (r.Count > 0 && r.Until != "") || (len(r.ByDay) > 0 && r.Freq != "WEEKLY") {
		return r, bad
	}
	sort.Slice(r.ByDay, func(i, j int) bool { return (r.ByDay[i]+6)%7 < (r.ByDay[j]+6)%7 })
	return r, nil
}

func indexOf(list []string, v string) int {
	for i, s := range list {
		if s == v {
			return i
		}
	}
	return -1
}

// String renders the rule; until is the UNTIL value already formatted for the
// event kind (DATE for all-day, UTC DATE-TIME otherwise), or "" to omit it.
func (r Rule) String(until string) string {
	out := "FREQ=" + r.Freq
	if r.Interval > 1 {
		out += fmt.Sprintf(";INTERVAL=%d", r.Interval)
	}
	if r.Count > 0 {
		out += fmt.Sprintf(";COUNT=%d", r.Count)
	}
	if until != "" {
		out += ";UNTIL=" + until
	}
	if len(r.ByDay) > 0 {
		codes := make([]string, len(r.ByDay))
		for i, d := range r.ByDay {
			codes[i] = dayCodes[d]
		}
		out += ";BYDAY=" + strings.Join(codes, ",")
	}
	return out
}

// Starts walks occurrence starts (wall time in start's location) in order,
// calling yield until it returns false. EXDATEs are the caller's concern, but
// they still count toward COUNT as RFC 5545 requires.
func (r Rule) Starts(start time.Time, yield func(time.Time) bool) {
	loc := start.Location()
	y, m, d := start.Date()
	hh, mm, ss := start.Clock()
	at := func(y int, m time.Month, d int) (time.Time, bool) {
		t := time.Date(y, m, d, hh, mm, ss, 0, loc)
		return t, t.Day() == d
	}
	n := 0
	emit := func(t time.Time) bool {
		if r.Until != "" && t.Format("2006-01-02") > r.Until {
			return false
		}
		n++
		if !yield(t) || (r.Count > 0 && n >= r.Count) || n >= maxOccurrences {
			return false
		}
		return true
	}
	for k := 0; k < maxOccurrences*7; k++ {
		step := k * r.Interval
		switch r.Freq {
		case "DAILY":
			t, _ := at(y, m, d+step)
			if !emit(t) {
				return
			}
		case "WEEKLY":
			if len(r.ByDay) == 0 {
				t, _ := at(y, m, d+7*step)
				if !emit(t) {
					return
				}
				continue
			}
			monday := d - int((start.Weekday()+6)%7) + 7*step
			for _, wd := range r.ByDay {
				t, _ := at(y, m, monday+int((wd+6)%7))
				if t.Before(start) {
					continue
				}
				if !emit(t) {
					return
				}
			}
		case "MONTHLY":
			if t, ok := at(y, m+time.Month(step), d); ok && !emit(t) {
				return
			}
		case "YEARLY":
			if t, ok := at(y+step, m, d); ok && !emit(t) {
				return
			}
		}
	}
}

// LastEnd is when the final occurrence ends, or nil for an endless series.
func (r Rule) LastEnd(start time.Time, length time.Duration) *time.Time {
	if r.Count == 0 && r.Until == "" {
		return nil
	}
	last := start
	r.Starts(start, func(t time.Time) bool { last = t; return true })
	end := last.Add(length)
	return &end
}
