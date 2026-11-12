package calendar

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Room is a bookable meeting room of a workspace.
type Room struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Capacity int    `json:"capacity"`
}

func (s *Store) Rooms(ctx context.Context, ws string) ([]Room, error) {
	rows, err := s.pool.Query(ctx, `SELECT id::text,name,capacity FROM calendar_rooms WHERE workspace_id=$1 ORDER BY lower(name)`, ws)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Room{}
	for rows.Next() {
		var r Room
		if err = rows.Scan(&r.ID, &r.Name, &r.Capacity); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) CreateRoom(ctx context.Context, ws, name string, capacity int) error {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > 100 || capacity < 0 || capacity > 10000 {
		return invalid("Название переговорной — до 100 символов, вместимость 0–10000")
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO calendar_rooms(workspace_id,name,capacity) VALUES($1,$2,$3)`, ws, name, capacity)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return invalid("Переговорная с таким названием уже есть")
	}
	return err
}

func (s *Store) DeleteRoom(ctx context.Context, ws, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM calendar_rooms WHERE workspace_id=$1 AND id::text=$2`, ws, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// withRoom puts the booked room's name in front of the place, for mail and feeds.
func withRoom(e Event, names map[string]string) Event {
	if name := names[e.RoomID]; name != "" {
		if e.Location == "" {
			e.Location = name
		} else {
			e.Location = name + ", " + e.Location
		}
	}
	return e
}

func (s *Store) roomNames(ctx context.Context, ws string) map[string]string {
	out := map[string]string{}
	rooms, err := s.Rooms(ctx, ws)
	if err == nil {
		for _, r := range rooms {
			out[r.ID] = r.Name
		}
	}
	return out
}

type span struct{ a, b time.Time }

// spans are an event's occupied intervals within [from,to); all-day dates
// count from midnight to midnight in the event zone.
func spans(e Event, from, to time.Time) []span {
	list := []Event{e}
	if e.RRule != "" {
		list = expand(e, from, to, from.Format("2006-01-02"), to.Format("2006-01-02"))
	}
	var out []span
	for _, o := range list {
		if len(out) >= 1000 {
			break
		}
		if o.AllDay {
			loc, err := Zone(o.Timezone)
			if err != nil {
				loc = time.UTC
			}
			a, err1 := time.ParseInLocation("2006-01-02", o.Start, loc)
			b, err2 := time.ParseInLocation("2006-01-02", o.End, loc)
			if err1 == nil && err2 == nil {
				out = append(out, span{a, b})
			}
		} else if o.StartAt != nil && o.EndAt != nil {
			out = append(out, span{*o.StartAt, *o.EndAt})
		}
	}
	return out
}

type queryRower interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

// roomEvents loads confirmed events booking the room that may touch [from,to).
func roomEvents(ctx context.Context, db queryRower, ws, room, except string, from, to time.Time) ([]Event, error) {
	rows, err := db.Query(ctx, `SELECT `+columns+` FROM calendar_events e JOIN calendars c ON c.id=e.calendar_id
		WHERE c.workspace_id=$1 AND e.room_id::text=$2 AND e.id::text<>$3 AND e.status='confirmed'
		AND ((e.rrule='' AND coalesce(e.end_at,e.end_date::timestamptz+interval '1 day')>$4 AND coalesce(e.start_at,e.start_date::timestamptz-interval '1 day')<$5)
		OR (e.rrule<>'' AND coalesce(e.start_at,e.start_date::timestamptz-interval '1 day')<$5 AND (e.series_until IS NULL OR e.series_until+interval '1 day'>$4)))
		LIMIT 500`, ws, room, except, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		e, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// checkRoom rejects a booking that overlaps another meeting in the same room
// within the next year of the event. Saves of one room are serialized.
func (s *Store) checkRoom(ctx context.Context, tx pgx.Tx, ws, id string, in Input, start, end time.Time) error {
	if in.RoomID == "" {
		return nil
	}
	var name string
	err := tx.QueryRow(ctx, `SELECT name FROM calendar_rooms WHERE id::text=$1 AND workspace_id=$2`, in.RoomID, ws).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		return invalid("Переговорная не найдена")
	}
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('calendar-room:'||$1,0))`, in.RoomID); err != nil {
		return err
	}
	e := Event{Input: in}
	if !in.AllDay {
		a, b := start.UTC(), end.UTC()
		e.StartAt, e.EndAt = &a, &b
	}
	first, _ := time.Parse("2006-01-02", in.Start[:10])
	from, to := first.AddDate(0, 0, -1), first.AddDate(1, 0, 1)
	mine := spans(e, from, to)
	others, err := roomEvents(ctx, tx, ws, in.RoomID, id, from, to)
	if err != nil {
		return err
	}
	loc, _ := Zone(in.Timezone)
	for _, o := range others {
		for _, x := range spans(o, from, to) {
			for _, m := range mine {
				if x.a.Before(m.b) && x.b.After(m.a) {
					return invalid(fmt.Sprintf("Переговорная «%s» занята: %s, %s–%s", name, ruDay(x.a.In(loc)), x.a.In(loc).Format("15:04"), x.b.In(loc).Format("15:04")))
				}
			}
		}
	}
	return nil
}

// RoomBusy lists when rooms are booked in [from,to) (dates in the zone).
func (s *Store) RoomBusy(ctx context.Context, ws string, rooms []string, from, to string, zone *time.Location) (map[string][]Busy, error) {
	a, err1 := time.ParseInLocation("2006-01-02", from, zone)
	b, err2 := time.ParseInLocation("2006-01-02", to, zone)
	if err1 != nil || err2 != nil || len(rooms) > 20 {
		return nil, invalid("Неверный диапазон или слишком много переговорных")
	}
	out := map[string][]Busy{}
	for _, room := range rooms {
		events, err := roomEvents(ctx, s.pool, ws, room, "", a, b)
		if err != nil {
			return nil, err
		}
		busy := []Busy{}
		for _, e := range events {
			for _, x := range spans(e, a, b) {
				if x.a.Before(b) && x.b.After(a) {
					sa, sb := x.a.UTC(), x.b.UTC()
					busy = append(busy, Busy{StartAt: &sa, EndAt: &sb})
				}
			}
		}
		out["room:"+room] = busy
	}
	return out, nil
}
