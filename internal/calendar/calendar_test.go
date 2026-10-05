package calendar

import (
	"testing"
	"time"
)

func TestEventTimes(t *testing.T) {
	for _, test := range []struct {
		name, start, end, zone string
		allDay, valid          bool
	}{
		{"Almaty", "2026-10-05T23:30", "2026-10-06T01:00", "Asia/Almaty", false, true},
		{"all day", "2026-10-05", "2026-10-07", "Asia/Almaty", true, true},
		{"backwards", "2026-10-05", "2026-10-04", "UTC", true, false},
		{"same instant", "2026-10-05T09:00", "2026-10-05T09:00", "UTC", false, false},
		{"invalid zone", "2026-10-05T09:00", "2026-10-05T10:00", "Bad/Zone", false, false},
		{"DST gap", "2026-03-08T02:30", "2026-03-08T04:00", "America/New_York", false, false},
		{"DST fold", "2026-11-01T01:30", "2026-11-01T03:00", "America/New_York", false, false},
		{"DST normal", "2026-03-08T01:30", "2026-03-08T03:30", "America/New_York", false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, start, end, err := Validate(Input{Title: "Meeting", Start: test.start, End: test.end, Timezone: test.zone, AllDay: test.allDay})
			if (err == nil) != test.valid {
				t.Fatalf("err=%v", err)
			}
			if test.name == "DST normal" && end.Sub(start) != time.Hour {
				t.Fatal("wrong DST duration")
			}
			if test.name == "Almaty" && start.UTC().Hour() != 18 {
				t.Fatal("wrong timezone")
			}
		})
	}
}
