package calendar

import (
	"fmt"
	"time"
)

var ruWeekdays = [...]string{"вс", "пн", "вт", "ср", "чт", "пт", "сб"}
var ruMonths = [...]string{"января", "февраля", "марта", "апреля", "мая", "июня", "июля", "августа", "сентября", "октября", "ноября", "декабря"}

func ruDay(t time.Time) string {
	return fmt.Sprintf("%s, %d %s %d", ruWeekdays[t.Weekday()], t.Day(), ruMonths[t.Month()-1], t.Year())
}

// HumanRange renders an event's time for people, e.g.
// "чт, 12 ноября 2026, 10:00–11:00 (Asia/Almaty)"; all-day ends are inclusive.
func HumanRange(e Event) string {
	if e.AllDay {
		start, err1 := time.Parse("2006-01-02", e.Start)
		end, err2 := time.Parse("2006-01-02", e.End)
		if err1 != nil || err2 != nil {
			return e.Start + " — " + e.End
		}
		last := end.AddDate(0, 0, -1)
		if !last.After(start) {
			return ruDay(start) + ", весь день"
		}
		return ruDay(start) + " — " + ruDay(last)
	}
	if e.StartAt == nil || e.EndAt == nil {
		return e.Start + " — " + e.End
	}
	loc, err := Zone(e.Timezone)
	if err != nil {
		loc = time.UTC
	}
	a, b := e.StartAt.In(loc), e.EndAt.In(loc)
	if a.Format("2006-01-02") == b.Format("2006-01-02") {
		return fmt.Sprintf("%s, %s–%s (%s)", ruDay(a), a.Format("15:04"), b.Format("15:04"), loc)
	}
	return fmt.Sprintf("%s, %s — %s, %s (%s)", ruDay(a), a.Format("15:04"), ruDay(b), b.Format("15:04"), loc)
}
