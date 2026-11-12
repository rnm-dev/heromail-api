// Package push stores where a user's mobile apps can be notified: one FCM
// registration token per signed-in session. Sending lives elsewhere (MAL-3);
// this package only answers "which tokens" and records "this token is dead".
package push

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrValidation = errors.New("validation failed")

// Device is one registration, without the token: the API never echoes it.
type Device struct {
	ID         string
	SessionID  string
	Platform   string
	Provider   string
	Locale     *string
	Timezone   *string
	AppVersion *string
	CreatedAt  time.Time
	LastSeenAt time.Time
	DisabledAt *time.Time
}

// Registration is what an app sends for its current session.
type Registration struct {
	Token      string
	Platform   string
	Provider   string
	Locale     string
	Timezone   string
	AppVersion string
}

// Target is a deliverable token, for the sender.
type Target struct {
	DeviceID string
	Token    string
	Platform string
	Locale   *string
}

type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

const deviceColumns = ` id, session_id, platform::text, provider::text, locale, timezone, app_version, created_at, last_seen_at, disabled_at`

func scanDevice(row pgx.Row) (*Device, error) {
	var d Device
	err := row.Scan(&d.ID, &d.SessionID, &d.Platform, &d.Provider, &d.Locale, &d.Timezone,
		&d.AppVersion, &d.CreatedAt, &d.LastSeenAt, &d.DisabledAt)
	return &d, err
}

func (r *Registration) normalise() error {
	r.Token = strings.TrimSpace(r.Token)
	r.Platform = strings.ToLower(strings.TrimSpace(r.Platform))
	r.Provider = strings.ToLower(strings.TrimSpace(r.Provider))
	if r.Provider == "" {
		r.Provider = "fcm"
	}
	switch {
	case r.Token == "" || len(r.Token) > 4096:
		return fmt.Errorf("%w: token is required (at most 4096 characters)", ErrValidation)
	case r.Platform != "ios" && r.Platform != "android":
		return fmt.Errorf("%w: platform must be ios or android", ErrValidation)
	case r.Provider != "fcm":
		return fmt.Errorf("%w: provider must be fcm", ErrValidation)
	case len(r.Locale) > 35 || len(r.Timezone) > 64 || len(r.AppVersion) > 50:
		return fmt.Errorf("%w: locale, timezone or app_version is too long", ErrValidation)
	}
	return nil
}

// Register upserts the session's registration. A token already held by
// another session — another account signed in on the same phone, or a stale
// session of this one — moves here: a token belongs to one session only.
func (s *Store) Register(ctx context.Context, userID, sessionID string, reg Registration) (*Device, error) {
	if err := reg.normalise(); err != nil {
		return nil, err
	}
	// Two sessions registering one token at the same moment collide on the
	// unique index; the loser simply retries and takes it over.
	for attempt := 0; ; attempt++ {
		d, err := s.register(ctx, userID, sessionID, reg)
		var pgErr *pgconn.PgError
		if err != nil && attempt < 2 && errors.As(err, &pgErr) && pgErr.Code == "23505" {
			continue
		}
		return d, err
	}
}

func (s *Store) register(ctx context.Context, userID, sessionID string, reg Registration) (*Device, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `DELETE FROM push_devices WHERE token = $1 AND session_id <> $2`, reg.Token, sessionID); err != nil {
		return nil, err
	}
	d, err := scanDevice(tx.QueryRow(ctx, `
		INSERT INTO push_devices (user_id, session_id, platform, provider, token, locale, timezone, app_version)
		VALUES ($1, $2, $3::push_platform, $4::push_provider, $5, nullif($6, ''), nullif($7, ''), nullif($8, ''))
		ON CONFLICT (session_id) DO UPDATE SET
		    platform = EXCLUDED.platform, provider = EXCLUDED.provider, token = EXCLUDED.token,
		    locale = EXCLUDED.locale, timezone = EXCLUDED.timezone, app_version = EXCLUDED.app_version,
		    last_seen_at = now(), disabled_at = NULL
		RETURNING`+deviceColumns,
		userID, sessionID, reg.Platform, reg.Provider, reg.Token, reg.Locale, reg.Timezone, reg.AppVersion))
	if err != nil {
		return nil, err
	}
	return d, tx.Commit(ctx)
}

// Unregister drops the session's registration; absent is not an error.
func (s *Store) Unregister(ctx context.Context, sessionID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM push_devices WHERE session_id = $1`, sessionID)
	return err
}

// DisableToken records that the provider rejected a token (FCM UNREGISTERED).
// The row stays so the device remains visible, but Targets skips it.
func (s *Store) DisableToken(ctx context.Context, token string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE push_devices SET disabled_at = now() WHERE token = $1 AND disabled_at IS NULL`, token)
	return err
}

// Targets lists a user's deliverable tokens: enabled, on a live session.
func (s *Store) Targets(ctx context.Context, userID string) ([]Target, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT p.id, p.token, p.platform::text, p.locale
		FROM push_devices p JOIN sessions s ON s.id = p.session_id
		WHERE p.user_id = $1 AND p.disabled_at IS NULL
		  AND s.revoked_at IS NULL AND s.expires_at > now()
		ORDER BY p.created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Target
	for rows.Next() {
		var t Target
		if err := rows.Scan(&t.DeviceID, &t.Token, &t.Platform, &t.Locale); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
