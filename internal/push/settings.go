package push

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	_ "time/tzdata" // quiet hours resolve IANA zones even in a bare container

	"github.com/jackc/pgx/v5"

	"github.com/rnm/heromail/backend/internal/inbound"
)

var (
	// ErrVersionConflict means the settings changed on another device.
	ErrVersionConflict = errors.New("notification settings changed elsewhere")
	// ErrUnknownMailbox is a mailbox the user cannot read — indistinguishable
	// from one that does not exist.
	ErrUnknownMailbox = errors.New("mailbox not found")
)

// Categories a mailbox can notify about, in display order.
var Categories = []string{"people", "notifications", "newsletters"}

// QuietHours are local wall-clock "HH:MM" times; Start > End wraps midnight.
type QuietHours struct {
	Start, End, Timezone string
}

// MailboxSettings is one readable mailbox's switches.
type MailboxSettings struct {
	MailboxID, Address, Workspace string
	Enabled                       bool
	Categories                    []string
	StarredOnly                   bool
}

// Settings is the whole document a user edits.
type Settings struct {
	Version   int
	Enabled   bool
	Privacy   bool
	Quiet     *QuietHours
	Mailboxes []MailboxSettings
}

// Defaults: everything on, people only, no privacy mode, no quiet hours —
// what MAL-3 sent before settings existed.
func defaultMailbox(m inbound.ReadableMailbox) MailboxSettings {
	return MailboxSettings{MailboxID: m.ID, Address: m.Address, Workspace: m.Workspace,
		Enabled: true, Categories: []string{"people"}}
}

// Settings returns the user's settings with every readable mailbox listed,
// defaults filled in for mailboxes never configured.
func (s *Store) Settings(ctx context.Context, userID string) (*Settings, error) {
	out := &Settings{Enabled: true}
	var start, end, tz *string
	err := s.pool.QueryRow(ctx, `SELECT version, enabled, privacy, to_char(quiet_start, 'HH24:MI'), to_char(quiet_end, 'HH24:MI'), timezone
		FROM notification_settings WHERE user_id = $1`, userID).
		Scan(&out.Version, &out.Enabled, &out.Privacy, &start, &end, &tz)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if start != nil {
		out.Quiet = &QuietHours{Start: *start, End: *end, Timezone: *tz}
	}
	boxes, err := inbound.NewStore(s.pool).ReadableMailboxes(ctx, userID)
	if err != nil {
		return nil, err
	}
	stored := map[string]MailboxSettings{}
	rows, err := s.pool.Query(ctx, `SELECT mailbox_id::text, enabled, categories, starred_only
		FROM mailbox_notification_settings WHERE user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var m MailboxSettings
		if err := rows.Scan(&m.MailboxID, &m.Enabled, &m.Categories, &m.StarredOnly); err != nil {
			rows.Close()
			return nil, err
		}
		stored[m.MailboxID] = m
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Only readable mailboxes are listed: a row left over from lost access
	// is neither shown nor applied.
	for _, b := range boxes {
		m := defaultMailbox(b)
		if st, ok := stored[b.ID]; ok {
			m.Enabled, m.Categories, m.StarredOnly = st.Enabled, st.Categories, st.StarredOnly
		}
		out.Mailboxes = append(out.Mailboxes, m)
	}
	return out, nil
}

// MailboxUpdate changes one mailbox; mailboxes not mentioned keep their settings.
type MailboxUpdate struct {
	MailboxID   string
	Enabled     bool
	Categories  []string
	StarredOnly bool
}

// SettingsUpdate replaces the global switches and the listed mailboxes.
type SettingsUpdate struct {
	Version   int
	Enabled   bool
	Privacy   bool
	Quiet     *QuietHours
	Mailboxes []MailboxUpdate
}

func validate(u *SettingsUpdate) error {
	if q := u.Quiet; q != nil {
		start, err1 := time.Parse("15:04", q.Start)
		end, err2 := time.Parse("15:04", q.End)
		if err1 != nil || err2 != nil {
			return fmt.Errorf("%w: quiet hours must be HH:MM", ErrValidation)
		}
		if start.Equal(end) {
			return fmt.Errorf("%w: quiet hours must not start and end at the same time", ErrValidation)
		}
		if q.Timezone == "" || len(q.Timezone) > 64 {
			return fmt.Errorf("%w: quiet hours need a timezone", ErrValidation)
		}
		if _, err := time.LoadLocation(q.Timezone); err != nil || strings.EqualFold(q.Timezone, "local") {
			return fmt.Errorf("%w: unknown timezone %q", ErrValidation, q.Timezone)
		}
	}
	seen := map[string]bool{}
	for i := range u.Mailboxes {
		m := &u.Mailboxes[i]
		if seen[m.MailboxID] {
			return fmt.Errorf("%w: mailbox %s listed twice", ErrValidation, m.MailboxID)
		}
		seen[m.MailboxID] = true
		var cats []string
		for _, c := range m.Categories {
			if !slices.Contains(Categories, c) {
				return fmt.Errorf("%w: unknown category %q", ErrValidation, c)
			}
			if !slices.Contains(cats, c) {
				cats = append(cats, c)
			}
		}
		m.Categories = cats
	}
	return nil
}

// SaveSettings applies an update if Version is current. A repeat of the write
// that produced the current version is not a conflict, so a client that lost
// the response can resend it.
func (s *Store) SaveSettings(ctx context.Context, userID string, u SettingsUpdate) (*Settings, error) {
	if err := validate(&u); err != nil {
		return nil, err
	}
	if len(u.Mailboxes) > 0 {
		ids := make([]string, len(u.Mailboxes))
		for i, m := range u.Mailboxes {
			ids[i] = m.MailboxID
		}
		allowed, err := inbound.NewStore(s.pool).AccessibleMailboxes(ctx, userID, ids)
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			if !allowed[id] {
				return nil, ErrUnknownMailbox
			}
		}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO notification_settings (user_id) VALUES ($1) ON CONFLICT DO NOTHING`, userID); err != nil {
		return nil, err
	}
	var version int
	if err := tx.QueryRow(ctx, `SELECT version FROM notification_settings WHERE user_id = $1 FOR UPDATE`, userID).Scan(&version); err != nil {
		return nil, err
	}
	if version == u.Version+1 {
		// A resend of the write that produced this version (the client lost
		// the response) is answered with the current state, not a conflict.
		if same, err := s.sameAsStored(ctx, tx, userID, u); err != nil {
			return nil, err
		} else if same {
			tx.Rollback(ctx)
			return s.Settings(ctx, userID)
		}
	}
	if version != u.Version {
		return nil, ErrVersionConflict
	}
	var start, end, tz any
	if u.Quiet != nil {
		start, end, tz = u.Quiet.Start, u.Quiet.End, u.Quiet.Timezone
	}
	if _, err := tx.Exec(ctx, `UPDATE notification_settings
		SET enabled = $2, privacy = $3, quiet_start = $4::time, quiet_end = $5::time, timezone = $6,
		    version = version + 1, updated_at = now()
		WHERE user_id = $1`, userID, u.Enabled, u.Privacy, start, end, tz); err != nil {
		return nil, err
	}
	for _, m := range u.Mailboxes {
		if m.Categories == nil {
			m.Categories = []string{}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO mailbox_notification_settings (user_id, mailbox_id, enabled, categories, starred_only)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (user_id, mailbox_id) DO UPDATE SET enabled = EXCLUDED.enabled,
			    categories = EXCLUDED.categories, starred_only = EXCLUDED.starred_only`,
			userID, m.MailboxID, m.Enabled, m.Categories, m.StarredOnly); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.Settings(ctx, userID)
}

func (s *Store) sameAsStored(ctx context.Context, tx pgx.Tx, userID string, u SettingsUpdate) (bool, error) {
	var enabled, privacy bool
	var start, end, tz *string
	if err := tx.QueryRow(ctx, `SELECT enabled, privacy, to_char(quiet_start, 'HH24:MI'), to_char(quiet_end, 'HH24:MI'), timezone
		FROM notification_settings WHERE user_id = $1`, userID).Scan(&enabled, &privacy, &start, &end, &tz); err != nil {
		return false, err
	}
	if enabled != u.Enabled || privacy != u.Privacy || (start == nil) != (u.Quiet == nil) {
		return false, nil
	}
	if u.Quiet != nil && (*start != u.Quiet.Start || *end != u.Quiet.End || *tz != u.Quiet.Timezone) {
		return false, nil
	}
	for _, m := range u.Mailboxes {
		var on, starred bool
		var cats []string
		err := tx.QueryRow(ctx, `SELECT enabled, categories, starred_only FROM mailbox_notification_settings
			WHERE user_id = $1 AND mailbox_id = $2`, userID, m.MailboxID).Scan(&on, &cats, &starred)
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if on != m.Enabled || starred != m.StarredOnly || !slices.Equal(cats, m.Categories) {
			return false, nil
		}
	}
	return true, nil
}

// delivery is what the sender needs to decide about one user and mailbox.
type delivery struct {
	enabled, privacy bool
	quiet            *QuietHours
	mailbox          MailboxSettings
}

func (s *Store) deliverySettings(ctx context.Context, userID, mailboxID string) (delivery, error) {
	d := delivery{enabled: true, mailbox: MailboxSettings{Enabled: true, Categories: []string{"people"}}}
	var start, end, tz *string
	err := s.pool.QueryRow(ctx, `SELECT enabled, privacy, to_char(quiet_start, 'HH24:MI'), to_char(quiet_end, 'HH24:MI'), timezone
		FROM notification_settings WHERE user_id = $1`, userID).Scan(&d.enabled, &d.privacy, &start, &end, &tz)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return d, err
	}
	if start != nil {
		d.quiet = &QuietHours{Start: *start, End: *end, Timezone: *tz}
	}
	err = s.pool.QueryRow(ctx, `SELECT enabled, categories, starred_only FROM mailbox_notification_settings
		WHERE user_id = $1 AND mailbox_id = $2`, userID, mailboxID).
		Scan(&d.mailbox.Enabled, &d.mailbox.Categories, &d.mailbox.StarredOnly)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return d, err
	}
	return d, nil
}

// wants reports whether a visible push for m should go out at now.
func (d delivery) wants(m *inbound.Message, now time.Time) bool {
	if !d.enabled || !d.mailbox.Enabled || !slices.Contains(d.mailbox.Categories, m.Category) {
		return false
	}
	if d.mailbox.StarredOnly && !m.Starred {
		return false
	}
	return !d.quiet.contains(now)
}

// contains reports whether now falls inside the quiet window, in its zone.
func (q *QuietHours) contains(now time.Time) bool {
	if q == nil {
		return false
	}
	loc, err := time.LoadLocation(q.Timezone)
	if err != nil {
		return false
	}
	start, err1 := time.Parse("15:04", q.Start)
	end, err2 := time.Parse("15:04", q.End)
	if err1 != nil || err2 != nil {
		return false
	}
	local := now.In(loc)
	minute := local.Hour()*60 + local.Minute()
	from, to := start.Hour()*60+start.Minute(), end.Hour()*60+end.Minute()
	if from < to {
		return minute >= from && minute < to
	}
	return minute >= from || minute < to
}
