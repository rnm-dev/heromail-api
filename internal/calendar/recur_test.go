package calendar

import (
	"testing"
	"time"
)

func starts(t *testing.T, rule string, start time.Time, n int) []string {
	t.Helper()
	r, err := ParseRule(rule)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	r.Starts(start, func(s time.Time) bool { out = append(out, s.Format("2006-01-02 15:04")); return len(out) < n })
	return out
}

func TestRuleExpansion(t *testing.T) {
	almaty, _ := time.LoadLocation("Asia/Almaty")
	berlin, _ := time.LoadLocation("Europe/Berlin")
	cases := []struct {
		rule  string
		start time.Time
		want  []string
	}{
		{"FREQ=DAILY;COUNT=3", time.Date(2026, 11, 30, 10, 0, 0, 0, almaty), []string{"2026-11-30 10:00", "2026-12-01 10:00", "2026-12-02 10:00"}},
		{"FREQ=WEEKLY;BYDAY=MO,WE,FR", time.Date(2026, 11, 11, 9, 0, 0, 0, almaty), []string{"2026-11-11 09:00", "2026-11-13 09:00", "2026-11-16 09:00", "2026-11-18 09:00"}},
		{"FREQ=WEEKLY;INTERVAL=2", time.Date(2026, 11, 11, 9, 0, 0, 0, almaty), []string{"2026-11-11 09:00", "2026-11-25 09:00"}},
		{"FREQ=MONTHLY", time.Date(2027, 1, 31, 9, 0, 0, 0, almaty), []string{"2027-01-31 09:00", "2027-03-31 09:00", "2027-05-31 09:00"}},
		{"FREQ=YEARLY;UNTIL=20330101", time.Date(2028, 2, 29, 0, 0, 0, 0, time.UTC), []string{"2028-02-29 00:00", "2032-02-29 00:00"}},
		// Wall time survives the DST change.
		{"FREQ=WEEKLY;COUNT=2", time.Date(2026, 10, 20, 9, 0, 0, 0, berlin), []string{"2026-10-20 09:00", "2026-10-27 09:00"}},
	}
	for _, c := range cases {
		got := starts(t, c.rule, c.start, len(c.want)+1)
		if len(got) > len(c.want) && c.rule != "FREQ=WEEKLY;BYDAY=MO,WE,FR" && c.rule != "FREQ=WEEKLY;INTERVAL=2" && c.rule != "FREQ=MONTHLY" {
			t.Fatalf("%s: too many %v", c.rule, got)
		}
		for i, w := range c.want {
			if got[i] != w {
				t.Fatalf("%s: got %v want %v", c.rule, got, c.want)
			}
		}
	}
	for _, bad := range []string{"", "FREQ=HOURLY", "FREQ=DAILY;COUNT=2;UNTIL=20270101", "FREQ=MONTHLY;BYDAY=MO", "FREQ=DAILY;BYSETPOS=1"} {
		if _, err := ParseRule(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
