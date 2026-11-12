package account

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Client mirrors the session_client enum: which kind of app holds a session.
type Client string

const (
	ClientWeb     Client = "web"
	ClientIOS     Client = "ios"
	ClientAndroid Client = "android"
)

// Mobile reports whether the client gets a short access token plus a rotating
// refresh token instead of one long-lived bearer token.
func (c Client) Mobile() bool { return c == ClientIOS || c == ClientAndroid }

// ParseClient accepts the values the spec declares; anything else (including
// empty) is a web session, which is what every client was before MAL-1.
func ParseClient(v string) Client {
	switch Client(strings.ToLower(strings.TrimSpace(v))) {
	case ClientIOS:
		return ClientIOS
	case ClientAndroid:
		return ClientAndroid
	default:
		return ClientWeb
	}
}

const (
	// accessTTL is short because a mobile bearer token sits in memory of an
	// app that may be on a lost phone; the refresh token is what survives.
	accessTTL = 15 * time.Minute

	// refreshTTL slides: every rotation pushes the session's end out again, so
	// a phone used at least once every 90 days never has to sign in again.
	refreshTTL = 90 * 24 * time.Hour
)

var (
	// ErrAccessExpired is a live mobile session whose access token ran out.
	// It is distinct from ErrNotFound so the client knows to refresh rather
	// than send the user to the sign-in screen.
	ErrAccessExpired = errors.New("access token expired")
	// ErrRefreshInvalid covers unknown, expired and revoked refresh tokens.
	ErrRefreshInvalid = errors.New("refresh token is invalid or expired")
	// ErrRefreshReused means an already-rotated refresh token was presented
	// again. One of the two holders is not the legitimate app, and we cannot
	// tell which, so the whole session is revoked.
	ErrRefreshReused = errors.New("refresh token was already used; the session has been revoked")
)

// DeviceSession is one entry of the "your devices" list.
type DeviceSession struct {
	ID         string
	Client     Client
	DeviceName *string
	AppVersion *string
	UserAgent  *string
	IP         *string
	CreatedAt  time.Time
	LastSeenAt *time.Time
	ExpiresAt  time.Time
}

// dbtx is what both the pool and a transaction offer, so session creation can
// run inside the password-verification transaction or on its own.
type dbtx interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func trimTo(v string, n int) string {
	v = strings.TrimSpace(v)
	if len([]rune(v)) > n {
		v = string([]rune(v)[:n])
	}
	return v
}

// insertSession creates the session row and, for mobile clients, its first
// refresh token. Web sessions keep the original shape: one token, sessionTTL.
func insertSession(ctx context.Context, q dbtx, user *User, rc RequestContext) (*Credentials, error) {
	token, hash, err := newToken()
	if err != nil {
		return nil, err
	}
	client := ParseClient(string(rc.Client))
	creds := &Credentials{Token: token, User: user}

	lifetime := sessionTTL
	if client.Mobile() {
		lifetime = refreshTTL
	}
	var accessTTLArg any
	if client.Mobile() {
		accessTTLArg = accessTTL.String()
	}
	var sessionExpires time.Time
	var accessExpires *time.Time
	err = q.QueryRow(ctx, `
		INSERT INTO sessions (user_id, token_hash, user_agent, ip, expires_at, client, device_name, app_version, access_expires_at)
		VALUES ($1, $2, nullif($3, ''), nullif($4, '')::inet, now() + $5::interval, $6,
		        nullif($7, ''), nullif($8, ''), now() + $9::interval)
		RETURNING id, expires_at, access_expires_at`,
		user.ID, hash, rc.UserAgent, rc.IP, lifetime.String(), string(client),
		trimTo(rc.DeviceName, 200), trimTo(rc.AppVersion, 50), accessTTLArg,
	).Scan(&creds.SessionID, &sessionExpires, &accessExpires)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	creds.ExpiresAt = sessionExpires
	if !client.Mobile() {
		return creds, nil
	}

	creds.ExpiresAt = *accessExpires
	refresh, refreshHash, err := newToken()
	if err != nil {
		return nil, err
	}
	if _, err := q.Exec(ctx,
		`INSERT INTO session_refresh_tokens (session_id, token_hash, expires_at) VALUES ($1, $2, $3)`,
		creds.SessionID, refreshHash, sessionExpires); err != nil {
		return nil, fmt.Errorf("create refresh token: %w", err)
	}
	creds.RefreshToken = refresh
	creds.RefreshExpiresAt = &sessionExpires
	return creds, nil
}

// Refresh rotates a mobile session's credentials: the presented refresh token
// is spent, a new access token replaces the old one (which stops working at
// once), and a successor refresh token is issued. The session's end slides.
//
// Presenting a token that was already rotated revokes the session: either the
// app or an attacker holds a copy, and leaving the chain alive would let the
// attacker keep refreshing forever.
func (s *Service) Refresh(ctx context.Context, refreshToken string, rc RequestContext) (*Credentials, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return nil, ErrRefreshInvalid
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	// Lock the token row first: two concurrent refreshes with the same token
	// must not both see used_at IS NULL and both mint a successor.
	var tokenID, sessionID string
	var usedAt *time.Time
	var tokenExpires time.Time
	err = tx.QueryRow(ctx, `
		SELECT id, session_id, used_at, expires_at
		FROM session_refresh_tokens WHERE token_hash = $1 FOR UPDATE`,
		hashToken(refreshToken)).Scan(&tokenID, &sessionID, &usedAt, &tokenExpires)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrRefreshInvalid
	}
	if err != nil {
		return nil, err
	}

	var userID string
	var client Client
	var revokedAt *time.Time
	var sessionExpires time.Time
	if err = tx.QueryRow(ctx, `
		SELECT user_id, client::text, revoked_at, expires_at FROM sessions WHERE id = $1 FOR UPDATE`,
		sessionID).Scan(&userID, &client, &revokedAt, &sessionExpires); err != nil {
		return nil, err
	}

	if usedAt != nil {
		if revokedAt == nil {
			if _, err = tx.Exec(ctx, `UPDATE sessions SET revoked_at = now() WHERE id = $1`, sessionID); err != nil {
				return nil, err
			}
			if err = tx.Commit(ctx); err != nil {
				return nil, err
			}
		}
		return nil, ErrRefreshReused
	}
	now := time.Now()
	if revokedAt != nil || !sessionExpires.After(now) || !tokenExpires.After(now) {
		return nil, ErrRefreshInvalid
	}

	access, accessHash, err := newToken()
	if err != nil {
		return nil, err
	}
	refresh, refreshHash, err := newToken()
	if err != nil {
		return nil, err
	}
	creds := &Credentials{Token: access, RefreshToken: refresh, SessionID: sessionID}
	var accessExpires, newSessionExpires time.Time
	if err = tx.QueryRow(ctx, `
		UPDATE sessions
		SET token_hash = $2,
		    access_expires_at = now() + $3::interval,
		    expires_at = now() + $4::interval,
		    last_seen_at = now(),
		    app_version = coalesce(nullif($5, ''), app_version),
		    ip = coalesce(nullif($6, '')::inet, ip),
		    user_agent = coalesce(nullif($7, ''), user_agent)
		WHERE id = $1
		RETURNING access_expires_at, expires_at`,
		sessionID, accessHash, accessTTL.String(), refreshTTL.String(),
		trimTo(rc.AppVersion, 50), rc.IP, rc.UserAgent,
	).Scan(&accessExpires, &newSessionExpires); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx, `UPDATE session_refresh_tokens SET used_at = now() WHERE id = $1`, tokenID); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(ctx,
		`INSERT INTO session_refresh_tokens (session_id, token_hash, expires_at) VALUES ($1, $2, $3)`,
		sessionID, refreshHash, newSessionExpires); err != nil {
		return nil, err
	}
	user, err := scanUser(tx.QueryRow(ctx, `SELECT`+userColumns+` FROM users WHERE id = $1`, userID))
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	creds.User = user
	creds.ExpiresAt = accessExpires
	creds.RefreshExpiresAt = &newSessionExpires
	return creds, nil
}

// ListSessions returns the user's live sessions, most recently active first.
func (s *Service) ListSessions(ctx context.Context, userID string) ([]DeviceSession, error) {
	rows, err := s.store.pool.Query(ctx, `
		SELECT id, client::text, device_name, app_version, user_agent, host(ip), created_at, last_seen_at, expires_at
		FROM sessions
		WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()
		ORDER BY coalesce(last_seen_at, created_at) DESC, id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DeviceSession
	for rows.Next() {
		var d DeviceSession
		if err := rows.Scan(&d.ID, &d.Client, &d.DeviceName, &d.AppVersion, &d.UserAgent, &d.IP,
			&d.CreatedAt, &d.LastSeenAt, &d.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// RevokeSessionByID ends one of the user's own sessions. Another user's
// session id is ErrNotFound, indistinguishable from a made-up one. A revoked
// session's refresh chain dies with it: Refresh checks revoked_at.
func (s *Service) RevokeSessionByID(ctx context.Context, userID, sessionID string) error {
	tag, err := s.store.pool.Exec(ctx, `
		UPDATE sessions SET revoked_at = now()
		WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL AND expires_at > now()`, sessionID, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SessionClientInfo returns how a session identified itself, so a password
// change performed from a phone hands back a phone session, not a web one.
func (s *Service) SessionClientInfo(ctx context.Context, sessionID string) (RequestContext, error) {
	var rc RequestContext
	var device, version *string
	err := s.store.pool.QueryRow(ctx,
		`SELECT client::text, device_name, app_version FROM sessions WHERE id = $1`, sessionID).
		Scan(&rc.Client, &device, &version)
	if err != nil {
		return rc, err
	}
	if device != nil {
		rc.DeviceName = *device
	}
	if version != nil {
		rc.AppVersion = *version
	}
	return rc, nil
}
