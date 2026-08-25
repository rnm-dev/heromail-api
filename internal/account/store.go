package account

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrEmailTaken    = errors.New("email already registered")
	ErrSubjectLinked = errors.New("identity already linked to another user")
)

const uniqueViolation = "23505"

// Store is the only thing in this package that talks to Postgres.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// userColumns is for single-table queries; userColumnsQualified is for joins,
// where a bare `id` is ambiguous because identities and sessions have one too.
const (
	userColumns          = ` id, email, name, email_verified_at, created_at, updated_at`
	userColumnsQualified = ` u.id, u.email, u.name, u.email_verified_at, u.created_at, u.updated_at`
)

func scanUser(row pgx.Row) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.Name, &u.EmailVerifiedAt, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// CreateWithPassword inserts the user and their password identity together: a
// user with no way to sign in would be unreachable state.
func (s *Store) CreateWithPassword(ctx context.Context, email, name string, passwordHash []byte) (*User, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	user, err := scanUser(tx.QueryRow(ctx,
		`INSERT INTO users (email, name) VALUES ($1, $2) RETURNING`+userColumns, email, name))
	if err != nil {
		if isUnique(err) {
			return nil, ErrEmailTaken
		}
		return nil, fmt.Errorf("insert user: %w", err)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO identities (user_id, provider, subject, password_hash)
		VALUES ($1, 'password', lower($2), $3)`,
		user.ID, email, string(passwordHash))
	if err != nil {
		if isUnique(err) {
			return nil, ErrEmailTaken
		}
		return nil, fmt.Errorf("insert password identity: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return user, nil
}

// PasswordIdentity returns the user and stored hash for an email address.
func (s *Store) PasswordIdentity(ctx context.Context, email string) (*User, []byte, error) {
	var u User
	var hash string
	err := s.pool.QueryRow(ctx, `
		SELECT u.id, u.email, u.name, u.email_verified_at, u.created_at, u.updated_at,
		       i.password_hash
		FROM identities i JOIN users u ON u.id = i.user_id
		WHERE i.provider = 'password' AND i.subject = lower($1)`, email,
	).Scan(&u.ID, &u.Email, &u.Name, &u.EmailVerifiedAt, &u.CreatedAt, &u.UpdatedAt, &hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	return &u, []byte(hash), nil
}

// UserByExternalIdentity finds the user behind a provider subject.
func (s *Store) UserByExternalIdentity(ctx context.Context, provider Provider, subject string) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `
		SELECT`+userColumnsQualified+`
		FROM users u JOIN identities i ON i.user_id = u.id
		WHERE i.provider = $1 AND i.subject = $2`, provider, subject))
}

func (s *Store) UserByID(ctx context.Context, id string) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT`+userColumns+` FROM users WHERE id = $1`, id))
}

func (s *Store) UserByEmail(ctx context.Context, email string) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT`+userColumns+` FROM users WHERE email = $1`, email))
}

// LinkIdentity attaches an external identity to an existing user.
func (s *Store) LinkIdentity(ctx context.Context, userID string, ext ExternalIdentity) error {
	metadata := ext.Metadata
	if len(metadata) == 0 {
		metadata = json.RawMessage("null")
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO identities (user_id, provider, subject, metadata, last_login_at)
		VALUES ($1, $2, $3, $4, now())`,
		userID, ext.Provider, ext.Subject, metadata)
	if isUnique(err) {
		return ErrSubjectLinked
	}
	return err
}

// CreateUserWithIdentity creates a user straight from an SSO assertion, with no
// password. This is the path a first Google or Entra sign-in takes.
func (s *Store) CreateUserWithIdentity(ctx context.Context, ext ExternalIdentity) (*User, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var verifiedAt any
	if ext.EmailVerified {
		verifiedAt = time.Now()
	}

	user, err := scanUser(tx.QueryRow(ctx,
		`INSERT INTO users (email, name, email_verified_at) VALUES ($1, $2, $3) RETURNING`+userColumns,
		ext.Email, ext.Name, verifiedAt))
	if err != nil {
		if isUnique(err) {
			return nil, ErrEmailTaken
		}
		return nil, err
	}

	metadata := ext.Metadata
	if len(metadata) == 0 {
		metadata = json.RawMessage("null")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO identities (user_id, provider, subject, metadata, last_login_at)
		VALUES ($1, $2, $3, $4, now())`,
		user.ID, ext.Provider, ext.Subject, metadata); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return user, nil
}

func (s *Store) TouchIdentityLogin(ctx context.Context, provider Provider, subject string) {
	s.pool.Exec(ctx,
		`UPDATE identities SET last_login_at = now() WHERE provider = $1 AND subject = $2`,
		provider, subject)
}

// UpdatePassword replaces the hash on the user's password identity.
//
// It never creates one: an account that signs in only through SSO has no
// password, and letting a reset link mint one would quietly add a second way
// into an account the customer deliberately keeps behind their IdP.
func (s *Store) UpdatePassword(ctx context.Context, userID string, hash []byte) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE identities SET password_hash = $2
		 WHERE user_id = $1 AND provider = 'password'`, userID, string(hash))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// HasPasswordIdentity reports whether the user can sign in with a password.
func (s *Store) HasPasswordIdentity(ctx context.Context, userID string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM identities WHERE user_id = $1 AND provider = 'password')`,
		userID).Scan(&exists)
	return exists, err
}

// RevokeAllSessions ends every signed-in browser for a user.
func (s *Store) RevokeAllSessions(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`,
		userID)
	return err
}

// MarkEmailVerified is idempotent: verifying twice is not an error.
func (s *Store) MarkEmailVerified(ctx context.Context, userID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE users SET email_verified_at = coalesce(email_verified_at, now()) WHERE id = $1`,
		userID)
	return err
}

// ---------------------------------------------------------------- tokens

// IssueToken replaces any live token for this purpose with a new one, so an
// old link stops working the moment a new one is sent.
func (s *Store) IssueToken(ctx context.Context, userID string, purpose TokenPurpose, hash []byte, ttl time.Duration) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx,
		`DELETE FROM user_tokens WHERE user_id = $1 AND purpose = $2 AND consumed_at IS NULL`,
		userID, purpose); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO user_tokens (user_id, purpose, token_hash, expires_at)
		VALUES ($1, $2, $3, now() + $4::interval)`,
		userID, purpose, hash, ttl.String()); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ConsumeToken atomically marks a live token used and returns its user. The
// single UPDATE is what makes a token single-use even under concurrent clicks.
func (s *Store) ConsumeToken(ctx context.Context, purpose TokenPurpose, hash []byte) (string, error) {
	var userID string
	err := s.pool.QueryRow(ctx, `
		UPDATE user_tokens SET consumed_at = now()
		WHERE token_hash = $1 AND purpose = $2
		  AND consumed_at IS NULL AND expires_at > now()
		RETURNING user_id`, hash, purpose).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return userID, err
}

// ---------------------------------------------------------------- sessions

func (s *Store) CreateSession(ctx context.Context, userID string, hash []byte, userAgent, ip string, ttl time.Duration) (*Session, error) {
	var sess Session
	err := s.pool.QueryRow(ctx, `
		INSERT INTO sessions (user_id, token_hash, user_agent, ip, expires_at)
		VALUES ($1, $2, nullif($3, ''), nullif($4, '')::inet, now() + $5::interval)
		RETURNING id, user_id, user_agent, expires_at, revoked_at, last_seen_at, created_at`,
		userID, hash, userAgent, ip, ttl.String(),
	).Scan(&sess.ID, &sess.UserID, &sess.UserAgent, &sess.ExpiresAt,
		&sess.RevokedAt, &sess.LastSeenAt, &sess.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	return &sess, nil
}

// UserBySessionToken resolves a live session to its user. Expired and revoked
// sessions are simply absent.
func (s *Store) UserBySessionToken(ctx context.Context, hash []byte) (*User, string, *time.Time, error) {
	var u User
	var sessionID string
	var lastSeen *time.Time
	err := s.pool.QueryRow(ctx, `
		SELECT u.id, u.email, u.name, u.email_verified_at, u.created_at, u.updated_at,
		       s.id, s.last_seen_at
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > now()`, hash,
	).Scan(&u.ID, &u.Email, &u.Name, &u.EmailVerifiedAt, &u.CreatedAt, &u.UpdatedAt,
		&sessionID, &lastSeen)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", nil, ErrNotFound
	}
	if err != nil {
		return nil, "", nil, err
	}
	return &u, sessionID, lastSeen, nil
}

func (s *Store) TouchSession(ctx context.Context, sessionID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE sessions SET last_seen_at = now() WHERE id = $1`, sessionID)
	return err
}

func (s *Store) RevokeSession(ctx context.Context, hash []byte) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE sessions SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL`, hash)
	return err
}

func isUnique(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == uniqueViolation
}
