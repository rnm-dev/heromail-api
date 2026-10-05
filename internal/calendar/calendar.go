// Package calendar implements private, membership-scoped personal calendars.
package calendar

import (
	"context"
	"errors"
	"strings"
	"time"
	_ "time/tzdata"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("event not found")
var ErrConflict = errors.New("event changed; reload before saving")

type ValidationError struct{ Message string }

func (e ValidationError) Error() string { return e.Message }
func invalid(s string) error            { return ValidationError{s} }

type Settings struct {
	Timezone string `json:"timezone"`
}
type Input struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Location    string `json:"location"`
	Timezone    string `json:"timezone"`
	AllDay      bool   `json:"all_day"`
	Start       string `json:"start"`
	End         string `json:"end"`
	Version     int    `json:"version"`
}
type Event struct {
	Input
	ID      string     `json:"id"`
	StartAt *time.Time `json:"start_at,omitempty"`
	EndAt   *time.Time `json:"end_at,omitempty"`
}
type Store struct{ pool *pgxpool.Pool }

func NewStore(p *pgxpool.Pool) *Store { return &Store{p} }
func Zone(name string) (*time.Location, error) {
	if name == "" || name == "Local" || len(name) > 100 {
		return nil, invalid("Выберите часовой пояс IANA, например Asia/Almaty")
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, invalid("Неизвестный часовой пояс")
	}
	return loc, nil
}

// Nonexistent and ambiguous wall times are rejected rather than silently moved.
func Wall(value string, loc *time.Location) (time.Time, error) {
	const layout = "2006-01-02T15:04"
	t, err := time.ParseInLocation(layout, value, loc)
	if err != nil || t.Format(layout) != value {
		return time.Time{}, invalid("Некорректное время или пропущенный час при переводе часов")
	}
	for _, delta := range []time.Duration{-24 * time.Hour, -3 * time.Hour, 3 * time.Hour, 24 * time.Hour} {
		_, offset := t.Add(delta).Zone()
		_, current := t.Zone()
		other := t.Add(time.Duration(current-offset) * time.Second)
		if !other.Equal(t) && other.In(loc).Format(layout) == value {
			return time.Time{}, invalid("Время неоднозначно из-за перевода часов; выберите время вне повторяющегося часа")
		}
	}
	return t, nil
}
func Validate(in Input) (Input, time.Time, time.Time, error) {
	in.Title = strings.TrimSpace(in.Title)
	if in.Title == "" || utf8.RuneCountInString(in.Title) > 200 || len(in.Description) > 20000 || len(in.Location) > 2000 {
		return in, time.Time{}, time.Time{}, invalid("Проверьте название (до 200 символов), описание и место")
	}
	loc, err := Zone(in.Timezone)
	if err != nil {
		return in, time.Time{}, time.Time{}, err
	}
	var start, end time.Time
	if in.AllDay {
		start, err = time.Parse("2006-01-02", in.Start)
		if err == nil {
			end, err = time.Parse("2006-01-02", in.End)
		}
	} else {
		start, err = Wall(in.Start, loc)
		if err == nil {
			end, err = Wall(in.End, loc)
		}
	}
	if err != nil {
		return in, start, end, invalid(err.Error())
	}
	if !end.After(start) || end.Sub(start) > 366*24*time.Hour || start.Year() < 1900 || end.Year() > 2200 {
		return in, start, end, invalid("Конец должен быть позже начала; длительность не больше года, даты 1900–2200")
	}
	return in, start, end, nil
}
func (s *Store) ensure(ctx context.Context, ws, user string) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx, `INSERT INTO calendars(workspace_id,user_id) SELECT workspace_id,user_id FROM workspace_members WHERE workspace_id=$1 AND user_id=$2 ON CONFLICT(workspace_id,user_id) DO UPDATE SET user_id=EXCLUDED.user_id RETURNING id`, ws, user).Scan(&id)
	return id, err
}
func (s *Store) Settings(ctx context.Context, ws, user string, zone *string) (Settings, error) {
	if zone != nil {
		if _, err := Zone(*zone); err != nil {
			return Settings{}, err
		}
	}
	id, err := s.ensure(ctx, ws, user)
	if err != nil {
		return Settings{}, err
	}
	var out Settings
	if zone == nil {
		err = s.pool.QueryRow(ctx, `SELECT timezone FROM calendars WHERE id=$1`, id).Scan(&out.Timezone)
	} else {
		err = s.pool.QueryRow(ctx, `UPDATE calendars SET timezone=$2 WHERE id=$1 RETURNING timezone`, id, *zone).Scan(&out.Timezone)
	}
	return out, err
}

const columns = `e.id,e.title,e.description,e.location,e.timezone,e.all_day,e.start_at,e.end_at,e.start_date::text,e.end_date::text,e.version`

func scan(row pgx.Row) (Event, error) {
	var out Event
	var start, end *string
	err := row.Scan(&out.ID, &out.Title, &out.Description, &out.Location, &out.Timezone, &out.AllDay, &out.StartAt, &out.EndAt, &start, &end, &out.Version)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if out.AllDay {
		out.Start = *start
		out.End = *end
	} else {
		loc, err := Zone(out.Timezone)
		if err != nil {
			return out, err
		}
		out.Start = out.StartAt.In(loc).Format("2006-01-02T15:04")
		out.End = out.EndAt.In(loc).Format("2006-01-02T15:04")
	}
	return out, nil
}
func (s *Store) List(ctx context.Context, ws, user, from, to string, offset int) ([]Event, bool, error) {
	a, err := time.Parse("2006-01-02", from)
	if err != nil {
		return nil, false, invalid("Неверное начало диапазона")
	}
	b, err := time.Parse("2006-01-02", to)
	if err != nil || !b.After(a) || b.Sub(a) > 93*24*time.Hour || offset < 0 || offset > 100000 {
		return nil, false, invalid("Диапазон должен быть от 1 до 93 дней")
	}
	settings, err := s.Settings(ctx, ws, user, nil)
	if err != nil {
		return nil, false, err
	}
	loc, _ := Zone(settings.Timezone)
	start := time.Date(a.Year(), a.Month(), a.Day(), 0, 0, 0, 0, loc)
	end := time.Date(b.Year(), b.Month(), b.Day(), 0, 0, 0, 0, loc)
	rows, err := s.pool.Query(ctx, `SELECT `+columns+` FROM calendar_events e JOIN calendars c ON c.id=e.calendar_id WHERE c.workspace_id=$1 AND c.user_id=$2 AND ((e.all_day AND e.start_date<$4::date AND e.end_date>$3::date) OR (NOT e.all_day AND e.start_at<$6 AND e.end_at>$5)) ORDER BY coalesce(e.start_at,e.start_date::timestamp AT TIME ZONE 'UTC'),e.id LIMIT 201 OFFSET $7`, ws, user, from, to, start, end, offset)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		e, err := scan(rows)
		if err != nil {
			return nil, false, err
		}
		out = append(out, e)
	}
	more := len(out) > 200
	if more {
		out = out[:200]
	}
	return out, more, rows.Err()
}
func (s *Store) Save(ctx context.Context, ws, user, id string, in Input) (Event, error) {
	in, start, end, err := Validate(in)
	if err != nil {
		return Event{}, err
	}
	var at, until, day, last any
	if in.AllDay {
		day = in.Start
		last = in.End
	} else {
		at = start
		until = end
	}
	if id == "" {
		if in.Version != 0 {
			return Event{}, invalid("Версия нового события должна быть 0")
		}
		cal, err := s.ensure(ctx, ws, user)
		if err != nil {
			return Event{}, err
		}
		return scan(s.pool.QueryRow(ctx, `INSERT INTO calendar_events AS e(calendar_id,title,description,location,timezone,all_day,start_at,end_at,start_date,end_date) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING `+columns, cal, in.Title, in.Description, in.Location, in.Timezone, in.AllDay, at, until, day, last))
	}
	if in.Version < 1 {
		return Event{}, invalid("Версия события обязательна")
	}
	out, err := scan(s.pool.QueryRow(ctx, `UPDATE calendar_events e SET title=$4,description=$5,location=$6,timezone=$7,all_day=$8,start_at=$9,end_at=$10,start_date=$11,end_date=$12,version=e.version+1,updated_at=now() FROM calendars c WHERE e.calendar_id=c.id AND c.workspace_id=$1 AND c.user_id=$2 AND e.id=$3 AND e.version=$13 RETURNING `+columns, ws, user, id, in.Title, in.Description, in.Location, in.Timezone, in.AllDay, at, until, day, last, in.Version))
	if errors.Is(err, ErrNotFound) {
		err = s.missing(ctx, ws, user, id)
	}
	return out, err
}
func (s *Store) missing(ctx context.Context, ws, user, id string) error {
	var exists bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM calendar_events e JOIN calendars c ON c.id=e.calendar_id WHERE c.workspace_id=$1 AND c.user_id=$2 AND e.id=$3)`, ws, user, id).Scan(&exists)
	if err != nil {
		return err
	}
	if exists {
		return ErrConflict
	}
	return ErrNotFound
}
func (s *Store) Delete(ctx context.Context, ws, user, id string, version int) error {
	if version < 1 {
		return invalid("Версия события обязательна")
	}
	result, err := s.pool.Exec(ctx, `DELETE FROM calendar_events e USING calendars c WHERE e.calendar_id=c.id AND c.workspace_id=$1 AND c.user_id=$2 AND e.id=$3 AND e.version=$4`, ws, user, id, version)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return s.missing(ctx, ws, user, id)
	}
	return nil
}
