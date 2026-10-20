// Package mailauth authenticates mail protocol logins (IMAP, SMTP submission)
// so that every protocol applies the same lookup, timing and rate limits.
package mailauth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/ratelimit"
	"golang.org/x/crypto/bcrypt"
)

// Kind selects which credential a lookup resolves.
type Kind int

const (
	// Account is the mailbox owner's own account password.
	Account Kind = iota
	// Application is a send-only mailbox SMTP password issued by an administrator.
	Application
)

// Principal is an authenticated mailbox login. Hash is the credential hash the
// login matched; callers compare it later to revoke sessions after changes.
type Principal struct {
	UserID, MailboxID, WorkspaceID, Hash string
	Kind                                 Kind
}

type queryRower interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

var queries = map[Kind]string{
	Account: `SELECT wm.user_id,m.id,w.id,i.password_hash FROM mailboxes m JOIN domains d ON d.id=m.domain_id
 JOIN workspaces w ON w.id=coalesce(m.personal_workspace_id,d.workspace_id)
 JOIN workspace_members wm ON wm.workspace_id=w.id AND wm.user_id=coalesce(m.owner_user_id,w.personal_owner_id)
 JOIN users u ON u.id=wm.user_id JOIN identities i ON i.user_id=u.id AND i.provider='password'
 WHERE lower(m.local_part||'@'||d.domain)=$1 AND d.verified_at IS NOT NULL AND NOT u.must_change_password`,
	// A mailbox password delegates sending only. Its issuer must still administer the
	// workspace; assignment and membership changes revoke the stored credential.
	Application: `SELECT c.issued_by,m.id,w.id,c.password_hash
 FROM mailbox_smtp_credentials c JOIN mailboxes m ON m.id=c.mailbox_id
 JOIN domains d ON d.id=m.domain_id JOIN workspaces w ON w.id=coalesce(m.personal_workspace_id,d.workspace_id)
 JOIN workspace_members wm ON wm.workspace_id=w.id AND wm.user_id=c.issued_by AND wm.role IN ('owner','admin')
 WHERE lower(m.local_part||'@'||d.domain)=$1 AND d.verified_at IS NOT NULL`,
}

// dummyHash is compared against for unknown addresses so response time does not
// reveal which mailboxes exist.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("mailauth-unknown-address"), account.BcryptCost)

// Allow applies the login limits shared by all mail protocols: per client IP and
// per address, failing closed when the limiter is unavailable. A nil limiter allows.
func Allow(ctx context.Context, l *ratelimit.Limiter, protocol, ip, address string) bool {
	if l == nil {
		return true
	}
	return l.AllowStrict(ctx, ratelimit.Rule{Name: protocol + ":login:ip", Limit: 30, Window: time.Minute}, ip).Allowed &&
		l.AllowStrict(ctx, ratelimit.Rule{Name: protocol + ":login:address", Limit: 30, Window: 15 * time.Minute}, address).Allowed
}

// Lookup resolves the current credential of the given kind for an address.
func Lookup(ctx context.Context, q queryRower, address string, kind Kind) (Principal, error) {
	p := Principal{Kind: kind}
	err := q.QueryRow(ctx, queries[kind], address).Scan(&p.UserID, &p.MailboxID, &p.WorkspaceID, &p.Hash)
	return p, err
}

// Login checks password against each allowed credential kind in order. Address
// must already be normalised to lower case.
func Login(ctx context.Context, q queryRower, address, password string, kinds ...Kind) (Principal, bool) {
	for _, kind := range kinds {
		p, err := Lookup(ctx, q, address, kind)
		if err != nil {
			bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(p.Hash), []byte(password)) == nil {
			return p, true
		}
	}
	return Principal{}, false
}
