// Package calendar implements private, membership-scoped personal calendars.
package calendar

import (
	"context"
	"errors"
	"net/mail"
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
	Title           string   `json:"title"`
	Description     string   `json:"description"`
	Location        string   `json:"location"`
	Timezone        string   `json:"timezone"`
	AllDay          bool     `json:"all_day"`
	Start           string   `json:"start"`
	End             string   `json:"end"`
	Version         int      `json:"version"`
	Organizer       string   `json:"organizer"`
	Attendees       []string `json:"attendees"`
	ReminderMinutes int      `json:"reminder_minutes"`
}
type Attendee struct {
	Email    string `json:"email"`
	Response string `json:"response"`
}
type Notification struct {
	Kind      string `json:"kind"`
	Recipient string `json:"recipient"`
	Status    string `json:"status"`
	Error     string `json:"error,omitempty"`
}
type Event struct {
	Input
	ID            string         `json:"id"`
	StartAt       *time.Time     `json:"start_at,omitempty"`
	EndAt         *time.Time     `json:"end_at,omitempty"`
	UID           string         `json:"uid"`
	Sequence      int            `json:"sequence"`
	Status        string         `json:"status"`
	Role          string         `json:"role"`
	InviteToken   string         `json:"invite_token,omitempty"`
	Responses     []Attendee     `json:"responses"`
	Notifications []Notification `json:"notifications"`
	UpdatedAt     time.Time      `json:"-"`
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
	if in.ReminderMinutes != 0 && in.ReminderMinutes != 10 && in.ReminderMinutes != 30 && in.ReminderMinutes != 60 {
		return in, start, end, invalid("Напоминание должно быть выключено или за 10, 30, 60 минут")
	}
	in.Organizer = strings.ToLower(strings.TrimSpace(in.Organizer))
	if in.Organizer != "" && !plainAddress(in.Organizer) {
		return in, start, end, invalid("Проверьте адрес организатора")
	}
	if len(in.Attendees) > 20 || ((len(in.Attendees) > 0 || in.ReminderMinutes > 0) && in.Organizer == "") {
		return in, start, end, invalid("Для приглашений выберите организатора и не более 20 участников")
	}
	seen := make(map[string]bool, len(in.Attendees))
	for i, addr := range in.Attendees {
		addr = strings.ToLower(strings.TrimSpace(addr))
		if !plainAddress(addr) || addr == in.Organizer || seen[addr] {
			return in, start, end, invalid("Проверьте список участников: адреса должны быть уникальными и отличаться от организатора")
		}
		seen[addr] = true
		in.Attendees[i] = addr
	}
	return in, start, end, nil
}
func plainAddress(value string) bool {
	parsed, err := mail.ParseAddress(value)
	return err == nil && parsed.Address == value && parsed.Name == "" && !strings.ContainsAny(value, "\r\n")
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

const columns = `e.id,e.title,e.description,e.location,e.timezone,e.all_day,e.start_at,e.end_at,e.start_date::text,e.end_date::text,e.version,e.organizer_email,e.uid,e.sequence,e.status,e.reminder_minutes,e.updated_at`

func scan(row pgx.Row) (Event, error) {
	return scanRecord(row, false)
}
func scanList(row pgx.Row) (Event, error) { return scanRecord(row, true) }
func scanRecord(row pgx.Row, list bool) (Event, error) {
	var out Event
	var start, end *string
	dest := []any{&out.ID, &out.Title, &out.Description, &out.Location, &out.Timezone, &out.AllDay, &out.StartAt, &out.EndAt, &start, &end, &out.Version, &out.Organizer, &out.UID, &out.Sequence, &out.Status, &out.ReminderMinutes, &out.UpdatedAt}
	var recipient, response string
	var sortAt time.Time
	if list {
		dest = append(dest, &out.Role, &out.InviteToken, &recipient, &response, &sortAt)
	}
	err := row.Scan(dest...)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	if list && out.Role == "attendee" {
		out.Attendees = []string{recipient}
		out.Responses = []Attendee{{Email: recipient, Response: response}}
	} else {
		out.Role = "organizer"
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
	rows, err := s.pool.Query(ctx, `SELECT * FROM (
		SELECT `+columns+`, 'organizer'::text AS role, ''::text AS token, ''::text AS recipient, ''::text AS response,coalesce(e.start_at,e.start_date::timestamp AT TIME ZONE 'UTC') AS sort_at
		FROM calendar_events e JOIN calendars c ON c.id=e.calendar_id WHERE c.workspace_id=$1 AND c.user_id=$2
		AND ((e.all_day AND e.start_date<$4::date AND e.end_date>$3::date) OR (NOT e.all_day AND e.start_at<$6 AND e.end_at>$5))
		UNION ALL
		SELECT `+columns+`, 'attendee'::text, a.response_token::text,i.recipient,a.response,coalesce(e.start_at,e.start_date::timestamp AT TIME ZONE 'UTC')
		FROM calendar_imports i JOIN calendars c ON c.id=i.calendar_id JOIN calendar_events e ON e.id=i.event_id
		JOIN calendar_attendees a ON a.event_id=i.event_id AND a.email=i.recipient
		WHERE c.workspace_id=$1 AND c.user_id=$2
		AND ((e.all_day AND e.start_date<$4::date AND e.end_date>$3::date) OR (NOT e.all_day AND e.start_at<$6 AND e.end_at>$5))
		UNION ALL
		SELECT x.id,x.title,x.description,x.location,x.timezone,x.all_day,x.start_at,x.end_at,x.start_date::text,x.end_date::text,1,x.organizer_email,x.uid,x.sequence,'confirmed'::text,0,x.updated_at,
		'attendee'::text,''::text,x.attendee,x.response,coalesce(x.start_at,x.start_date::timestamp AT TIME ZONE 'UTC')
		FROM calendar_external_events x JOIN calendars c ON c.id=x.calendar_id
		WHERE c.workspace_id=$1 AND c.user_id=$2
		AND ((x.all_day AND x.start_date<$4::date AND x.end_date>$3::date) OR (NOT x.all_day AND x.start_at<$6 AND x.end_at>$5))
	) items ORDER BY sort_at,id LIMIT 201 OFFSET $7`, ws, user, from, to, start, end, offset)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		e, err := scanList(rows)
		if err != nil {
			return nil, false, err
		}
		if e.Role == "organizer" {
			if err := s.loadAttendees(ctx, s.pool, &e); err != nil {
				return nil, false, err
			}
			if err := s.loadNotifications(ctx, s.pool, &e); err != nil {
				return nil, false, err
			}
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
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Event{}, err
	}
	defer tx.Rollback(ctx)
	var out Event
	var old Event
	changed := true
	if id == "" {
		if in.Version != 0 {
			return Event{}, invalid("Версия нового события должна быть 0")
		}
		cal, err := s.ensure(ctx, ws, user)
		if err != nil {
			return Event{}, err
		}
		out, err = scan(tx.QueryRow(ctx, `INSERT INTO calendar_events AS e(calendar_id,title,description,location,timezone,all_day,start_at,end_at,start_date,end_date,organizer_email,reminder_minutes) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING `+columns, cal, in.Title, in.Description, in.Location, in.Timezone, in.AllDay, at, until, day, last, in.Organizer, in.ReminderMinutes))
		if err != nil {
			return Event{}, err
		}
	} else {
		if in.Version < 1 {
			return Event{}, invalid("Версия события обязательна")
		}
		old, err = scan(tx.QueryRow(ctx, `SELECT `+columns+` FROM calendar_events e JOIN calendars c ON c.id=e.calendar_id WHERE c.workspace_id=$1 AND c.user_id=$2 AND e.id=$3 FOR UPDATE OF e`, ws, user, id))
		if errors.Is(err, ErrNotFound) {
			return Event{}, ErrNotFound
		}
		if err != nil {
			return Event{}, err
		}
		if old.Version != in.Version {
			return Event{}, ErrConflict
		}
		if old.Status == "cancelled" {
			return Event{}, invalid("Отменённую встречу нельзя изменить")
		}
		if err := s.loadAttendees(ctx, tx, &old); err != nil {
			return Event{}, err
		}
		if len(old.Attendees) > 0 && old.Organizer != in.Organizer {
			return Event{}, invalid("Нельзя сменить организатора встречи после приглашения")
		}
		// Only a change attendees would see bumps SEQUENCE and re-invites
		// everyone; only a new time asks them to answer again.
		retimed := old.AllDay != in.AllDay || old.Start != in.Start || old.End != in.End || old.Timezone != in.Timezone
		changed = retimed || old.Title != in.Title || old.Description != in.Description || old.Location != in.Location
		bump := 0
		if changed {
			bump = 1
		}
		out, err = scan(tx.QueryRow(ctx, `UPDATE calendar_events e SET title=$4,description=$5,location=$6,timezone=$7,all_day=$8,start_at=$9,end_at=$10,start_date=$11,end_date=$12,organizer_email=$14,reminder_minutes=$15,version=e.version+1,sequence=e.sequence+$16,updated_at=now() FROM calendars c WHERE e.calendar_id=c.id AND c.workspace_id=$1 AND c.user_id=$2 AND e.id=$3 AND e.version=$13 RETURNING `+columns, ws, user, id, in.Title, in.Description, in.Location, in.Timezone, in.AllDay, at, until, day, last, in.Version, in.Organizer, in.ReminderMinutes, bump))
		if err != nil {
			return Event{}, err
		}
		if _, err = tx.Exec(ctx, `UPDATE calendar_jobs SET status='skipped',updated_at=now() WHERE event_id=$1 AND status IN ('pending','failed')`, out.ID); err != nil {
			return Event{}, err
		}
		if retimed {
			if _, err = tx.Exec(ctx, `UPDATE calendar_attendees SET response='needs_action',responded_at=NULL WHERE event_id=$1`, out.ID); err != nil {
				return Event{}, err
			}
		}
	}
	current := make(map[string]bool, len(in.Attendees))
	for _, address := range in.Attendees {
		current[address] = true
		if _, err = tx.Exec(ctx, `INSERT INTO calendar_attendees(event_id,email) VALUES($1,$2) ON CONFLICT(event_id,email) DO NOTHING`, out.ID, address); err != nil {
			return Event{}, err
		}
		if !changed {
			var has bool
			if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM calendar_jobs WHERE event_id=$1 AND kind='request' AND recipient=$2 AND sequence=$3 AND status IN ('queued','processing'))`, out.ID, address, out.Sequence).Scan(&has); err != nil {
				return Event{}, err
			}
			if has {
				continue
			}
		}
		if err = s.addJob(ctx, tx, out, "request", address, time.Now()); err != nil {
			return Event{}, err
		}
	}
	for _, address := range old.Attendees {
		if current[address] {
			continue
		}
		if err = s.addJob(ctx, tx, out, "cancel", address, time.Now()); err != nil {
			return Event{}, err
		}
	}
	if _, err = tx.Exec(ctx, `DELETE FROM calendar_attendees WHERE event_id=$1 AND NOT(email=ANY($2::text[]))`, out.ID, in.Attendees); err != nil {
		return Event{}, err
	}
	if out.ReminderMinutes > 0 && out.Organizer != "" {
		when := start.Add(-time.Duration(out.ReminderMinutes) * time.Minute)
		if out.AllDay {
			loc, _ := Zone(out.Timezone)
			when = time.Date(start.Year(), start.Month(), start.Day(), 9, 0, 0, 0, loc).Add(-time.Duration(out.ReminderMinutes) * time.Minute)
		}
		if when.After(time.Now()) {
			if err = s.addJob(ctx, tx, out, "reminder", out.Organizer, when); err != nil {
				return Event{}, err
			}
		}
	}
	if err = s.loadAttendees(ctx, tx, &out); err != nil {
		return Event{}, err
	}
	if err = s.loadNotifications(ctx, tx, &out); err != nil {
		return Event{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Event{}, err
	}
	return out, nil
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
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	e, err := scan(tx.QueryRow(ctx, `SELECT `+columns+` FROM calendar_events e JOIN calendars c ON c.id=e.calendar_id WHERE c.workspace_id=$1 AND c.user_id=$2 AND e.id=$3 FOR UPDATE OF e`, ws, user, id))
	if errors.Is(err, ErrNotFound) {
		// Not our own event: a copy of someone else's meeting just leaves our calendar.
		tag, err := tx.Exec(ctx, `DELETE FROM calendar_imports i USING calendars c WHERE c.id=i.calendar_id AND c.workspace_id=$1 AND c.user_id=$2 AND i.event_id=$3`, ws, user, id)
		if err != nil {
			return err
		}
		removed := tag.RowsAffected()
		tag, err = tx.Exec(ctx, `DELETE FROM calendar_external_events x USING calendars c WHERE c.id=x.calendar_id AND c.workspace_id=$1 AND c.user_id=$2 AND x.id=$3`, ws, user, id)
		if err != nil {
			return err
		}
		if removed+tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return tx.Commit(ctx)
	}
	if err != nil {
		return err
	}
	if e.Version != version {
		return ErrConflict
	}
	if e.Status == "cancelled" {
		var pending bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM calendar_jobs WHERE event_id=$1 AND status IN ('pending','processing','failed'))`, id).Scan(&pending); err != nil {
			return err
		}
		if pending {
			return invalid("Уведомления об отмене ещё отправляются; уберите встречу чуть позже")
		}
		if _, err = tx.Exec(ctx, `DELETE FROM calendar_events WHERE id=$1`, id); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if err = s.loadAttendees(ctx, tx, &e); err != nil {
		return err
	}
	if len(e.Attendees) == 0 {
		_, err = tx.Exec(ctx, `DELETE FROM calendar_events WHERE id=$1`, id)
		if err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	e.Version++
	e.Sequence++
	_, err = tx.Exec(ctx, `UPDATE calendar_events SET status='cancelled',version=$2,sequence=$3,updated_at=now() WHERE id=$1`, id, e.Version, e.Sequence)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE calendar_jobs SET status='skipped',updated_at=now() WHERE event_id=$1 AND status IN ('pending','failed')`, id)
	if err != nil {
		return err
	}
	for _, address := range e.Attendees {
		if err = s.addJob(ctx, tx, e, "cancel", address, time.Now()); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

type queryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func (s *Store) loadAttendees(ctx context.Context, db queryer, e *Event) error {
	rows, err := db.Query(ctx, `SELECT email,response FROM calendar_attendees WHERE event_id=$1 ORDER BY email`, e.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	e.Attendees = []string{}
	e.Responses = []Attendee{}
	for rows.Next() {
		var a Attendee
		if err = rows.Scan(&a.Email, &a.Response); err != nil {
			return err
		}
		e.Attendees = append(e.Attendees, a.Email)
		e.Responses = append(e.Responses, a)
	}
	return rows.Err()
}
func (s *Store) addJob(ctx context.Context, tx pgx.Tx, e Event, kind, address string, due time.Time) error {
	_, err := tx.Exec(ctx, `INSERT INTO calendar_jobs(event_id,event_version,kind,recipient,due_at,sequence) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, e.ID, e.Version, kind, address, due, e.Sequence)
	return err
}
func (s *Store) loadNotifications(ctx context.Context, db queryer, e *Event) error {
	rows, err := db.Query(ctx, `SELECT j.kind,j.recipient,coalesce(m.status::text,j.status),coalesce(m.last_error,j.last_error,'') FROM calendar_jobs j LEFT JOIN emails m ON m.id=j.email_id WHERE j.event_id=$1 AND j.event_version=$2 ORDER BY j.created_at,j.id`, e.ID, e.Version)
	if err != nil {
		return err
	}
	defer rows.Close()
	e.Notifications = []Notification{}
	for rows.Next() {
		var n Notification
		if err = rows.Scan(&n.Kind, &n.Recipient, &n.Status, &n.Error); err != nil {
			return err
		}
		e.Notifications = append(e.Notifications, n)
	}
	return rows.Err()
}
