package inbound

import "context"

// Scoped writes repeat ownership checks at the database boundary.
func (s *Store) SetSMTPPassword(ctx context.Context, workspace, box, user, hash string) error {
	result, err := s.pool.Exec(ctx, `INSERT INTO mailbox_smtp_credentials(mailbox_id,password_hash,issued_by)
 SELECT m.id,$4,$3 FROM mailboxes m JOIN domains d ON d.id=m.domain_id
 JOIN workspace_members wm ON wm.workspace_id=coalesce(m.personal_workspace_id,d.workspace_id) AND wm.user_id=$3 AND wm.role IN ('owner','admin')
 WHERE m.id=$2 AND coalesce(m.personal_workspace_id,d.workspace_id)=$1
 ON CONFLICT(mailbox_id) DO UPDATE SET password_hash=EXCLUDED.password_hash,issued_by=EXCLUDED.issued_by,updated_at=now()`, workspace, box, user, hash)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrNoMailbox
	}
	return nil
}
func (s *Store) DeleteSMTPPassword(ctx context.Context, workspace, box string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM mailbox_smtp_credentials c USING mailboxes m,domains d WHERE c.mailbox_id=m.id AND m.domain_id=d.id AND m.id=$2 AND coalesce(m.personal_workspace_id,d.workspace_id)=$1`, workspace, box)
	return err
}
