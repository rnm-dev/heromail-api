// Package workspace owns tenants and who belongs to them.
package workspace

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound   = errors.New("workspace not found")
	ErrSlugTaken  = errors.New("slug is already taken")
	ErrValidation = errors.New("validation failed")
)

// slugPattern mirrors the CHECK constraint on workspaces.slug, so a slug the
// database would reject is rejected here with a useful message instead.
var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)

type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
)

type Workspace struct {
	ID        string
	Slug      string
	Name      string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Membership is a workspace plus the caller's role in it.
type Membership struct {
	Workspace
	Role Role
}

type Store struct{ pool *pgxpool.Pool }

func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

const columns = ` id, slug, name, created_at, updated_at`

func scan(row pgx.Row) (*Workspace, error) {
	var w Workspace
	err := row.Scan(&w.ID, &w.Slug, &w.Name, &w.CreatedAt, &w.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &w, nil
}

// Create inserts the workspace and makes the creator its owner, in one
// transaction: an ownerless workspace would be unreachable.
func (s *Store) Create(ctx context.Context, ownerID, slug, name string) (*Workspace, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	ws, err := scan(tx.QueryRow(ctx,
		`INSERT INTO workspaces (slug, name) VALUES ($1, $2) RETURNING`+columns, slug, name))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, ErrSlugTaken
		}
		return nil, fmt.Errorf("insert workspace: %w", err)
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ($1, $2, 'owner')`,
		ws.ID, ownerID); err != nil {
		return nil, fmt.Errorf("insert owner membership: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return ws, nil
}

// ListForUser returns the workspaces a user belongs to, with their role.
func (s *Store) ListForUser(ctx context.Context, userID string) ([]Membership, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT w.id, w.slug, w.name, w.created_at, w.updated_at, m.role
		FROM workspaces w JOIN workspace_members m ON m.workspace_id = w.id
		WHERE m.user_id = $1
		ORDER BY w.created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	memberships := []Membership{}
	for rows.Next() {
		var m Membership
		if err := rows.Scan(&m.ID, &m.Slug, &m.Name, &m.CreatedAt, &m.UpdatedAt, &m.Role); err != nil {
			return nil, err
		}
		memberships = append(memberships, m)
	}
	return memberships, rows.Err()
}

// BySlugForUser scopes the lookup to the caller's memberships, so a workspace
// they do not belong to is indistinguishable from one that does not exist.
func (s *Store) BySlugForUser(ctx context.Context, userID, slug string) (*Workspace, error) {
	return scan(s.pool.QueryRow(ctx, `
		SELECT w.id, w.slug, w.name, w.created_at, w.updated_at
		FROM workspaces w JOIN workspace_members m ON m.workspace_id = w.id
		WHERE m.user_id = $1 AND w.slug = $2`, userID, slug))
}

// MembershipRole returns the caller's role in a workspace, or ErrNotFound if
// they are not a member. Callers use it to separate "you cannot see this"
// (404) from "you may not change this" (403).
func (s *Store) MembershipRole(ctx context.Context, workspaceID, userID string) (Role, error) {
	var role Role
	err := s.pool.QueryRow(ctx,
		`SELECT role FROM workspace_members WHERE workspace_id = $1 AND user_id = $2`,
		workspaceID, userID).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return role, err
}

// ByID is unscoped, for callers that already proved their scope — the API key
// middleware, which resolved the workspace from the key itself.
func (s *Store) ByID(ctx context.Context, id string) (*Workspace, error) {
	return scan(s.pool.QueryRow(ctx, `SELECT`+columns+` FROM workspaces WHERE id = $1`, id))
}

// Service holds the rules.
type Service struct{ store *Store }

func NewService(store *Store) *Service { return &Service{store: store} }

func (s *Service) Create(ctx context.Context, ownerID, slug, name string) (*Workspace, error) {
	slug = strings.ToLower(strings.TrimSpace(slug))
	name = strings.TrimSpace(name)

	if !slugPattern.MatchString(slug) {
		return nil, fmt.Errorf(
			"%w: slug must be 3-63 characters of lowercase letters, digits or hyphens, "+
				"and start and end with a letter or digit", ErrValidation)
	}
	if name == "" {
		return nil, fmt.Errorf("%w: name is required", ErrValidation)
	}
	return s.store.Create(ctx, ownerID, slug, name)
}

func (s *Service) ListForUser(ctx context.Context, userID string) ([]Membership, error) {
	return s.store.ListForUser(ctx, userID)
}

func (s *Service) BySlugForUser(ctx context.Context, userID, slug string) (*Workspace, error) {
	return s.store.BySlugForUser(ctx, userID, slug)
}

func (s *Service) ByID(ctx context.Context, id string) (*Workspace, error) {
	return s.store.ByID(ctx, id)
}

func (s *Service) MembershipRole(ctx context.Context, workspaceID, userID string) (Role, error) {
	return s.store.MembershipRole(ctx, workspaceID, userID)
}

// rank orders roles by privilege so permission checks compare instead of
// enumerating cases.
func (r Role) rank() int {
	switch r {
	case RoleOwner:
		return 3
	case RoleAdmin:
		return 2
	case RoleMember:
		return 1
	default:
		return 0
	}
}

// AtLeast reports whether r carries at least the privileges of min.
func (r Role) AtLeast(min Role) bool { return r.rank() >= min.rank() }

// DeleteOwned repeats the ownership check in the write itself. Foreign keys
// remove tenant data atomically; global user accounts belong to no tenant.
func (s *Service) DeleteOwned(ctx context.Context, userID, slug string) error {
	result, err := s.store.pool.Exec(ctx, `DELETE FROM workspaces w WHERE w.slug=$1
 AND EXISTS (SELECT 1 FROM workspace_members m WHERE m.workspace_id=w.id AND m.user_id=$2 AND m.role='owner')`, slug, userID)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
