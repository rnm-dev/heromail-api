package calendar

import (
	"context"
	"strings"
)

// Person is a workspace member in sharing lists.
type Person struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// Shares lists who sees the caller's calendar and whose calendars the caller sees.
func (s *Store) Shares(ctx context.Context, ws, user string) (granted, withMe []Person, err error) {
	cal, err := s.ensure(ctx, ws, user)
	if err != nil {
		return nil, nil, err
	}
	granted, err = s.people(ctx, `SELECT u.id::text,u.email,u.name FROM calendar_shares sh JOIN users u ON u.id=sh.grantee_id WHERE sh.calendar_id=$1 ORDER BY lower(u.email)`, cal)
	if err != nil {
		return nil, nil, err
	}
	withMe, err = s.people(ctx, `SELECT u.id::text,u.email,u.name FROM calendar_shares sh JOIN calendars c ON c.id=sh.calendar_id JOIN users u ON u.id=c.user_id
		WHERE sh.workspace_id=$1 AND sh.grantee_id=$2 ORDER BY lower(u.name),lower(u.email)`, ws, user)
	return granted, withMe, err
}

func (s *Store) people(ctx context.Context, sql string, args ...any) ([]Person, error) {
	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Person{}
	for rows.Next() {
		var p Person
		if err = rows.Scan(&p.ID, &p.Email, &p.Name); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Share grants a colleague (by sign-in address) read access to the caller's calendar.
func (s *Store) Share(ctx context.Context, ws, user, email string) error {
	cal, err := s.ensure(ctx, ws, user)
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `INSERT INTO calendar_shares(calendar_id,workspace_id,grantee_id)
		SELECT $1,$2,u.id FROM users u JOIN workspace_members wm ON wm.user_id=u.id AND wm.workspace_id=$2 WHERE lower(u.email)=$3 AND u.id<>$4
		ON CONFLICT DO NOTHING`, cal, ws, strings.ToLower(strings.TrimSpace(email)), user)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if err = s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM calendar_shares sh JOIN users u ON u.id=sh.grantee_id WHERE sh.calendar_id=$1 AND lower(u.email)=$2)`, cal, strings.ToLower(strings.TrimSpace(email))).Scan(&exists); err != nil || exists {
			return err
		}
		return invalid("Такого участника нет в этом пространстве")
	}
	return nil
}

// Unshare removes a colleague's access to the caller's calendar.
func (s *Store) Unshare(ctx context.Context, ws, user, grantee string) error {
	cal, err := s.ensure(ctx, ws, user)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `DELETE FROM calendar_shares WHERE calendar_id=$1 AND grantee_id::text=$2`, cal, grantee)
	return err
}

// SharedEvents lists a colleague's events for a viewer they shared with:
// read-only, without attendee answers, delivery state or invitation links.
func (s *Store) SharedEvents(ctx context.Context, ws, viewer, owner, from, to string, offset int) ([]Event, bool, error) {
	var ok bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM calendar_shares sh JOIN calendars c ON c.id=sh.calendar_id
		WHERE sh.workspace_id=$1 AND sh.grantee_id=$2 AND c.user_id::text=$3 AND c.workspace_id=$1)`, ws, viewer, owner).Scan(&ok); err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, ErrNotFound
	}
	events, more, err := s.List(ctx, ws, owner, from, to, offset)
	for i := range events {
		e := &events[i]
		e.Role, e.InviteToken, e.Notifications = "shared", "", nil
		e.Responses, e.Attendees = nil, nil
		if e.Master != nil {
			m := *e.Master
			m.Attendees = nil
			e.Master = &m
		}
	}
	return events, more, err
}
