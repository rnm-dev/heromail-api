package account

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/rnm/heromail/backend/internal/provider"
)

// ErrNoPassword means the account cannot re-authenticate with a password
// (SSO-only). Nothing in production signs in that way yet.
var ErrNoPassword = errors.New("account has no password to confirm with")

// SoleOwnerError lists workspaces that would be left without an owner. The
// account is not deleted: the workspace has to be deleted, or ownership handed
// over (by support: a workspace has exactly one owner and there is no transfer
// endpoint yet), first — never decided silently on the user's behalf.
type SoleOwnerError struct{ Workspaces []string }

func (e *SoleOwnerError) Error() string {
	return "sole owner of workspaces: " + strings.Join(e.Workspaces, ", ")
}

// DeletionResult describes what deleting the account did, for the
// confirmation email and the log.
type DeletionResult struct {
	Email string
	// PersonalWorkspaces were deleted with their mailboxes and mail.
	PersonalWorkspaces []string
	// RetainedMailboxes are corporate mailboxes the user owned. They stay with
	// the workspace, unreadable by anyone until an owner reassigns them.
	RetainedMailboxes []string
}

// DeleteAccount re-checks the password and, in one transaction, removes every
// way to sign in and the user's personal data, deletes their personal
// workspace, leaves every other workspace, and anonymises the user row.
func (s *Service) DeleteAccount(ctx context.Context, userID, password string) (*DeletionResult, error) {
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	res := &DeletionResult{}
	if err := tx.QueryRow(ctx, `SELECT email FROM users WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`, userID).
		Scan(&res.Email); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var hash string
	err = tx.QueryRow(ctx, `SELECT password_hash FROM identities WHERE user_id = $1 AND provider = 'password'`, userID).Scan(&hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNoPassword
	}
	if err != nil {
		return nil, err
	}
	if !verifyPassword([]byte(hash), password) {
		return nil, ErrCredentials
	}

	// Lock every owner row of the workspaces this user owns, so a co-owner
	// cannot be demoted between the check and the deletion.
	if _, err := tx.Exec(ctx, `SELECT 1 FROM workspace_members WHERE role = 'owner' AND workspace_id IN
		(SELECT workspace_id FROM workspace_members WHERE user_id = $1 AND role = 'owner') FOR UPDATE`, userID); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT w.slug FROM workspace_members m JOIN workspaces w ON w.id = m.workspace_id
		WHERE m.user_id = $1 AND m.role = 'owner' AND w.personal_owner_id IS DISTINCT FROM $1
		  AND NOT EXISTS (SELECT 1 FROM workspace_members o
		                  WHERE o.workspace_id = m.workspace_id AND o.role = 'owner' AND o.user_id <> $1)
		ORDER BY w.slug`, userID)
	if err != nil {
		return nil, err
	}
	sole, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	if len(sole) > 0 {
		return nil, &SoleOwnerError{Workspaces: sole}
	}

	if rows, err = tx.Query(ctx, `SELECT m.local_part || '@' || d.domain FROM mailboxes m JOIN domains d ON d.id = m.domain_id
		WHERE m.owner_user_id = $1 AND m.personal_workspace_id IS NULL ORDER BY 1`, userID); err != nil {
		return nil, err
	}
	if res.RetainedMailboxes, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
		return nil, err
	}

	// The personal workspace is the user's alone: it goes, with its mailbox
	// and mail.
	if rows, err = tx.Query(ctx, `DELETE FROM workspaces WHERE personal_owner_id = $1 RETURNING slug`, userID); err != nil {
		return nil, err
	}
	if res.PersonalWorkspaces, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
		return nil, err
	}

	for _, q := range []string{
		// Sessions take their refresh tokens and push devices with them.
		`DELETE FROM sessions WHERE user_id = $1`,
		`DELETE FROM identities WHERE user_id = $1`,
		`DELETE FROM user_tokens WHERE user_id = $1`,
		`DELETE FROM mailbox_assistant_keys WHERE user_id = $1`,
		`DELETE FROM mailbox_smtp_credentials WHERE issued_by = $1`,
		`DELETE FROM contacts WHERE user_id = $1`,
		`DELETE FROM mail_drafts WHERE user_id = $1`,
		`DELETE FROM mail_signatures WHERE user_id = $1`,
		`DELETE FROM notification_settings WHERE user_id = $1`,
		`DELETE FROM mailbox_members WHERE user_id = $1`,
		// Unsent uploads keep pointing at the anonymised row, so nobody else
		// can attach them; clearing the owner would open them to the workspace.
		// Leaving every workspace takes the user's calendars and the shares
		// on them.
		`DELETE FROM workspace_members WHERE user_id = $1`,
		`UPDATE users SET email = 'deleted-' || id || '@deleted.invalid', name = '', email_verified_at = NULL,
		        must_change_password = false, deleted_at = now(), updated_at = now() WHERE id = $1`,
	} {
		if _, err := tx.Exec(ctx, q, userID); err != nil {
			return nil, fmt.Errorf("delete account: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	s.sendDeletionEmail(ctx, res)
	return res, nil
}

// sendDeletionEmail is best-effort: the account is already gone, and a mail
// outage must not make the deletion look failed.
func (s *Service) sendDeletionEmail(ctx context.Context, res *DeletionResult) {
	var b strings.Builder
	b.WriteString("Здравствуйте!\n\nВаш аккаунт Heromail удалён. Войти в него больше нельзя, все сессии и устройства отключены.\n")
	if len(res.PersonalWorkspaces) > 0 {
		b.WriteString("\nЛичный ящик и его почта удалены.\n")
	}
	if len(res.RetainedMailboxes) > 0 {
		b.WriteString("\nКорпоративные ящики остаются у организации, доступ к ним закрыт до решения её администратора: " +
			strings.Join(res.RetainedMailboxes, ", ") + ".\n")
	}
	b.WriteString("\nЕсли вы этого не делали, ответьте на это письмо.\n")
	if _, err := s.sender.Send(ctx, provider.Message{
		DKIM:     s.signMailFrom(ctx),
		From:     s.cfg.MailFrom,
		To:       []string{res.Email},
		Subject:  "Аккаунт Heromail удалён",
		TextBody: b.String(),
	}); err != nil {
		log.Printf("account: deletion confirmation to %s: %v", res.Email, err)
	}
}
