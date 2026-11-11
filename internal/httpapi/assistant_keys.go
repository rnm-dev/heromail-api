package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/mailauth"
	"golang.org/x/crypto/bcrypt"
)

// Personal AI assistant keys: the mailbox owner delegates IMAP reading and SMTP
// sending of their own mailbox. Only owned mailboxes qualify, the same rule as
// account-password IMAP, so a key never widens what its issuer could read.
const ownedMailboxes = `SELECT m.id,lower(m.local_part||'@'||d.domain),k.key_prefix,k.created_at
 FROM mailboxes m JOIN domains d ON d.id=m.domain_id JOIN workspaces w ON w.id=coalesce(m.personal_workspace_id,d.workspace_id)
 JOIN workspace_members wm ON wm.workspace_id=w.id AND wm.user_id=$1
 LEFT JOIN mailbox_assistant_keys k ON k.mailbox_id=m.id AND k.user_id=$1
 WHERE coalesce(m.owner_user_id,w.personal_owner_id)=$1 AND d.verified_at IS NOT NULL`

func (s *Server) ownedMailboxes(ctx context.Context, user string, only *string) ([]AssistantKey, error) {
	q, args := ownedMailboxes+` ORDER BY 2`, []any{user}
	if only != nil {
		q, args = ownedMailboxes+` AND m.id=$2`, []any{user, *only}
	}
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AssistantKey{}
	for rows.Next() {
		var k AssistantKey
		var id string
		if err := rows.Scan(&id, &k.Address, &k.KeyPrefix, &k.CreatedAt); err != nil {
			return nil, err
		}
		if err := k.MailboxId.UnmarshalText([]byte(id)); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Server) ListAssistantKeys(ctx context.Context, _ ListAssistantKeysRequestObject) (ListAssistantKeysResponseObject, error) {
	user, ok := account.CurrentUser(ctx)
	if !ok {
		return ListAssistantKeys401JSONResponse{UnauthorizedJSONResponse(errorBody("unauthenticated", "no session"))}, nil
	}
	boxes, err := s.ownedMailboxes(ctx, user.ID, nil)
	if err != nil {
		return nil, err
	}
	return ListAssistantKeys200JSONResponse{Mailboxes: boxes}, nil
}

func (s *Server) IssueAssistantKey(ctx context.Context, r IssueAssistantKeyRequestObject) (IssueAssistantKeyResponseObject, error) {
	user, ok := account.CurrentUser(ctx)
	if !ok {
		return IssueAssistantKey401JSONResponse{UnauthorizedJSONResponse(errorBody("unauthenticated", "no session"))}, nil
	}
	id := r.MailboxId.String()
	boxes, err := s.ownedMailboxes(ctx, user.ID, &id)
	if err != nil {
		return nil, err
	}
	if len(boxes) == 0 {
		return IssueAssistantKey404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "mailbox not found or not yours"))}, nil
	}
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	key := mailauth.AssistantKeyPrefix + hex.EncodeToString(raw)
	hash, err := bcrypt.GenerateFromPassword([]byte(key), account.BcryptCost)
	if err != nil {
		return nil, err
	}
	box := boxes[0]
	prefix, now := key[:len(mailauth.AssistantKeyPrefix)+4], time.Now()
	if _, err = s.pool.Exec(ctx, `INSERT INTO mailbox_assistant_keys(mailbox_id,user_id,key_hash,key_prefix,created_at) VALUES($1,$2,$3,$4,$5)
 ON CONFLICT(mailbox_id,user_id) DO UPDATE SET key_hash=EXCLUDED.key_hash,key_prefix=EXCLUDED.key_prefix,created_at=EXCLUDED.created_at`, id, user.ID, string(hash), prefix, now); err != nil {
		return nil, err
	}
	box.KeyPrefix, box.CreatedAt = &prefix, &now
	return IssueAssistantKey201JSONResponse{Key: key, Mailbox: box}, nil
}

func (s *Server) DeleteAssistantKey(ctx context.Context, r DeleteAssistantKeyRequestObject) (DeleteAssistantKeyResponseObject, error) {
	user, ok := account.CurrentUser(ctx)
	if !ok {
		return DeleteAssistantKey401JSONResponse{UnauthorizedJSONResponse(errorBody("unauthenticated", "no session"))}, nil
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM mailbox_assistant_keys WHERE mailbox_id=$1 AND user_id=$2`, r.MailboxId.String(), user.ID); err != nil {
		return nil, err
	}
	return DeleteAssistantKey204Response{}, nil
}
