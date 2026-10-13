package calendar

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
)

type Invitation struct {
	Event     Event  `json:"event"`
	Recipient string `json:"recipient"`
	Response  string `json:"response"`
}
type ResponseRequest struct {
	Response string `json:"response"`
}

func (s *Store) Invitation(ctx context.Context, token string) (Invitation, error) {
	var eventID, recipient, response string
	err := s.pool.QueryRow(ctx, `SELECT event_id,email,response FROM calendar_attendees WHERE response_token=$1`, token).Scan(&eventID, &recipient, &response)
	if errors.Is(err, pgx.ErrNoRows) {
		return Invitation{}, ErrNotFound
	}
	if err != nil {
		return Invitation{}, err
	}
	e, err := scan(s.pool.QueryRow(ctx, `SELECT `+columns+` FROM calendar_events e WHERE e.id=$1`, eventID))
	if err != nil {
		return Invitation{}, err
	}
	// A bearer link grants access to this recipient's invitation, not to the
	// organizer's whole calendar or other attendees' addresses.
	e.Attendees = nil
	e.Responses = nil
	e.Notifications = nil
	return Invitation{Event: e, Recipient: recipient, Response: response}, nil
}

func (s *Store) Respond(ctx context.Context, token, response string) (Invitation, error) {
	if response != "accepted" && response != "tentative" && response != "declined" {
		return Invitation{}, invalid("Выберите «Да», «Возможно» или «Нет»")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Invitation{}, err
	}
	defer tx.Rollback(ctx)
	var eventID, recipient, current string
	err = tx.QueryRow(ctx, `SELECT event_id FROM calendar_attendees WHERE response_token=$1`, token).Scan(&eventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return Invitation{}, ErrNotFound
	}
	if err != nil {
		return Invitation{}, err
	}
	e, err := scan(tx.QueryRow(ctx, `SELECT `+columns+` FROM calendar_events e WHERE e.id=$1 FOR SHARE`, eventID))
	if err != nil {
		return Invitation{}, err
	}
	if e.Status != "confirmed" {
		return Invitation{}, ErrConflict
	}
	err = tx.QueryRow(ctx, `SELECT email,response FROM calendar_attendees WHERE event_id=$1 AND response_token=$2 FOR UPDATE`, eventID, token).Scan(&recipient, &current)
	if errors.Is(err, pgx.ErrNoRows) {
		return Invitation{}, ErrNotFound
	}
	if err != nil {
		return Invitation{}, err
	}
	if response != current {
		var revision int
		err = tx.QueryRow(ctx, `UPDATE calendar_attendees SET response=$3,responded_at=now(),response_version=response_version+1 WHERE event_id=$1 AND email=$2 RETURNING response_version`, eventID, recipient, response).Scan(&revision)
		if err != nil {
			return Invitation{}, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO calendar_jobs(event_id,event_version,kind,recipient,actor,response,response_version) VALUES($1,$2,'reply',$3,$4,$5,$6)`, eventID, e.Version, e.Organizer, recipient, response, revision)
		if err != nil {
			return Invitation{}, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return Invitation{}, err
	}
	e.Attendees = nil
	e.Responses = nil
	e.Notifications = nil
	return Invitation{Event: e, Recipient: recipient, Response: response}, nil
}
