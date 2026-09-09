package inbound

import (
	"context"
	"errors"
)

// CanAccess is shared by the HTTP and IMAP adapters. Workspace management does
// not imply permission to read a private employee's correspondence.
func (s *Store) CanAccess(ctx context.Context, userID, mailboxID string) (bool, error) {
	var allowed bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mailboxes m JOIN domains d ON d.id=m.domain_id
 JOIN workspaces w ON w.id=coalesce(m.personal_workspace_id,d.workspace_id)
 JOIN workspace_members wm ON wm.workspace_id=w.id AND wm.user_id=$1
 WHERE m.id=$2 AND (coalesce(m.owner_user_id,w.personal_owner_id) IS NULL OR coalesce(m.owner_user_id,w.personal_owner_id)=$1))`, userID, mailboxID).Scan(&allowed)
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
	return nil
}

// CanReadOutbound also protects status/detail responses containing the body.
func (s *Store) CanReadOutbound(ctx context.Context, userID, emailID string) (bool, error) {
	var allowed bool
	err := s.pool.QueryRow(ctx, `SELECT (e.retained_owner_id IS NULL OR e.retained_owner_id::text=$1) AND NOT EXISTS(SELECT 1 FROM mailboxes m JOIN domains d ON d.id=m.domain_id WHERE coalesce(m.personal_workspace_id,d.workspace_id)=e.workspace_id AND lower(m.local_part || '@' || d.domain)=lower(e.from_addr) AND m.owner_user_id IS NOT NULL AND m.owner_user_id::text<>$1) FROM emails e WHERE e.id=$2`, userID, emailID).Scan(&allowed)
	return allowed, err
}
