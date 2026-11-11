package calendar

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// FeedToken returns the calendar's subscription token; rotate issues a new one
// (revoking the old URL) and disable turns the feed off.
func (s *Store) FeedToken(ctx context.Context, ws, user, action string) (string, error) {
	id, err := s.ensure(ctx, ws, user)
	if err != nil {
		return "", err
	}
	var token *string
	switch action {
	case "rotate":
		err = s.pool.QueryRow(ctx, `UPDATE calendars SET feed_token=gen_random_uuid() WHERE id=$1 RETURNING feed_token::text`, id).Scan(&token)
	case "disable":
		_, err = s.pool.Exec(ctx, `UPDATE calendars SET feed_token=NULL WHERE id=$1`, id)
	default:
		err = s.pool.QueryRow(ctx, `SELECT feed_token::text FROM calendars WHERE id=$1`, id).Scan(&token)
	}
	if err != nil || token == nil {
		return "", err
	}
	return *token, nil
}

// Feed renders a read-only iCalendar of the past 60 and next 365 days for a
// subscription token, including accepted copies of others' meetings.
func (s *Store) Feed(ctx context.Context, token string, now time.Time) (string, error) {
	var ws, user, zone string
	err := s.pool.QueryRow(ctx, `SELECT workspace_id::text,user_id::text,timezone FROM calendars WHERE feed_token=$1::uuid`, token).Scan(&ws, &user, &zone)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	seen := map[string]bool{}
	var events []Event
	day := now.UTC().AddDate(0, 0, -60)
	for i := 0; i < 5; i++ {
		from, to := day.Format("2006-01-02"), day.AddDate(0, 0, 85).Format("2006-01-02")
		for offset := 0; offset < 2000; {
			page, more, err := s.List(ctx, ws, user, from, to, offset)
			if err != nil {
				return "", err
			}
			for _, e := range page {
				if !seen[e.ID] {
					seen[e.ID] = true
					events = append(events, e)
				}
			}
			if !more {
				break
			}
			offset += len(page)
		}
		day = day.AddDate(0, 0, 85)
	}
	stamp := now.UTC().Format("20060102T150405Z")
	lines := []string{"BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Heromail//Calendar//EN", "CALSCALE:GREGORIAN", "METHOD:PUBLISH",
		"X-WR-CALNAME:Heromail", "X-WR-TIMEZONE:" + zone, "REFRESH-INTERVAL;VALUE=DURATION:PT15M", "X-PUBLISHED-TTL:PT15M"}
	for _, e := range events {
		lines = append(lines, "BEGIN:VEVENT", "UID:"+e.UID, "DTSTAMP:"+stamp, fmt.Sprintf("SEQUENCE:%d", e.Sequence),
			"SUMMARY:"+icsEscape(e.Title))
		if e.AllDay {
			lines = append(lines, "DTSTART;VALUE=DATE:"+strings.ReplaceAll(e.Start, "-", ""), "DTEND;VALUE=DATE:"+strings.ReplaceAll(e.End, "-", ""))
		} else {
			lines = append(lines, "DTSTART:"+e.StartAt.UTC().Format("20060102T150405Z"), "DTEND:"+e.EndAt.UTC().Format("20060102T150405Z"))
		}
		if e.Location != "" {
			lines = append(lines, "LOCATION:"+icsEscape(e.Location))
		}
		if e.Description != "" {
			lines = append(lines, "DESCRIPTION:"+icsEscape(e.Description))
		}
		if e.Organizer != "" {
			lines = append(lines, "ORGANIZER:mailto:"+e.Organizer)
		}
		if e.Status == "cancelled" {
			lines = append(lines, "STATUS:CANCELLED")
		} else {
			lines = append(lines, "STATUS:CONFIRMED")
		}
		lines = append(lines, "END:VEVENT")
	}
	lines = append(lines, "END:VCALENDAR")
	for i := range lines {
		lines[i] = foldICS(lines[i])
	}
	return strings.Join(lines, "\r\n") + "\r\n", nil
}
