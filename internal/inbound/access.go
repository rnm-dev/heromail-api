package inbound

import (
	"context"
	"errors"
	"slices"

	"github.com/jackc/pgx/v5"
)

// CanAccess is shared by the HTTP and IMAP adapters. Workspace management does
// not imply permission to read a private employee's correspondence.
func (s *Store) CanAccess(ctx context.Context, userID, mailboxID string) (bool, error) {
	var allowed bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mailboxes m JOIN domains d ON d.id=m.domain_id
 JOIN workspaces w ON w.id=coalesce(m.personal_workspace_id,d.workspace_id)
 JOIN workspace_members wm ON wm.workspace_id=w.id AND wm.user_id=$1
 WHERE m.id=$2 AND ((coalesce(m.owner_user_id,w.personal_owner_id) IS NULL AND NOT EXISTS(SELECT 1 FROM mailbox_members mx WHERE mx.mailbox_id=m.id)) OR coalesce(m.owner_user_id,w.personal_owner_id)=$1 OR EXISTS(SELECT 1 FROM mailbox_members mm WHERE mm.mailbox_id=m.id AND mm.user_id=$1)))`, userID, mailboxID).Scan(&allowed)
	return allowed, err
}

func (s *Store) AssignOwner(ctx context.Context, workspaceID, mailboxID string, owner *string) error {
	// An employee must belong to this workspace. A NULL owner explicitly shares
	// the mailbox. Personal workspaces cannot assign it to another account.
	result, err := s.pool.Exec(ctx, `UPDATE mailboxes m SET owner_user_id=$3 FROM domains d,workspaces w
 WHERE d.id=m.domain_id AND w.id=coalesce(m.personal_workspace_id,d.workspace_id) AND w.id=$1 AND m.id=$2
 AND ($3::uuid IS NULL OR EXISTS(SELECT 1 FROM workspace_members WHERE workspace_id=w.id AND user_id=$3))
 AND (w.personal_owner_id IS NULL OR $3::uuid=w.personal_owner_id)`, workspaceID, mailboxID, owner)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return errors.New("mailbox or workspace member not found")
	}
	// The owner needs no separate grant.
	_, err = s.pool.Exec(ctx, `DELETE FROM mailbox_members mm USING mailboxes m
 WHERE mm.mailbox_id=m.id AND m.id=$1 AND mm.user_id=m.owner_user_id`, mailboxID)
	return err
}

// SetMembers replaces the employees assigned to a mailbox besides its owner.
// Assigned employees read and send from it; once a shared mailbox has any, it
// is no longer open to the rest of the workspace. Each must be a workspace
// member; personal workspaces take no grants.
func (s *Store) SetMembers(ctx context.Context, workspaceID, mailboxID string, userIDs []string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var owner *string
	err = tx.QueryRow(ctx, `SELECT m.owner_user_id::text FROM mailboxes m JOIN domains d ON d.id=m.domain_id
 JOIN workspaces w ON w.id=coalesce(m.personal_workspace_id,d.workspace_id)
 WHERE m.id=$2 AND w.id=$1 AND w.personal_owner_id IS NULL FOR UPDATE OF m`, workspaceID, mailboxID).Scan(&owner)
	if errors.Is(err, pgx.ErrNoRows) {
		return errors.New("mailbox not found")
	}
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(userIDs))
	for _, id := range userIDs {
		if (owner == nil || id != *owner) && !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	var members int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM workspace_members WHERE workspace_id=$1 AND user_id::text=ANY($2)`, workspaceID, ids).Scan(&members); err != nil {
		return err
	}
	if members != len(ids) {
		return errors.New("every user must be a member of this workspace")
	}
	if _, err = tx.Exec(ctx, `DELETE FROM mailbox_members WHERE mailbox_id=$1 AND NOT (user_id::text=ANY($2))`, mailboxID, ids); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO mailbox_members(mailbox_id,user_id) SELECT $1,unnest($2::uuid[]) ON CONFLICT DO NOTHING`, mailboxID, ids); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// CanReadOutbound also protects status/detail responses containing the body.
func (s *Store) CanReadOutbound(ctx context.Context, userID, emailID string) (bool, error) {
	var allowed bool
	err := s.pool.QueryRow(ctx, `SELECT (e.retained_owner_id IS NULL OR e.retained_owner_id::text=$1) AND NOT EXISTS(SELECT 1 FROM mailboxes m JOIN domains d ON d.id=m.domain_id WHERE coalesce(m.personal_workspace_id,d.workspace_id)=e.workspace_id AND lower(m.local_part || '@' || d.domain)=lower(e.from_addr) AND (m.owner_user_id IS NOT NULL OR EXISTS(SELECT 1 FROM mailbox_members mx WHERE mx.mailbox_id=m.id)) AND m.owner_user_id::text IS DISTINCT FROM $1 AND NOT EXISTS(SELECT 1 FROM mailbox_members mm WHERE mm.mailbox_id=m.id AND mm.user_id::text=$1)) FROM emails e WHERE e.id=$2`, userID, emailID).Scan(&allowed)
	return allowed, err
}
