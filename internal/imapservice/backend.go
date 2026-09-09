// Package imapservice exposes the existing message store to standard IMAP clients.
package imapservice

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/backend"
	"github.com/emersion/go-imap/server"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rnm/heromail/backend/internal/inbound"
	"github.com/rnm/heromail/backend/internal/ratelimit"
	"golang.org/x/crypto/bcrypt"
)

type Backend struct {
	pool    *pgxpool.Pool
	access  *inbound.Store
	limiter *ratelimit.Limiter
}

func New(pool *pgxpool.Pool, limiter *ratelimit.Limiter) *Backend {
	return &Backend{pool: pool, access: inbound.NewStore(pool), limiter: limiter}
}
func Server(b *Backend, addr, cert, key string) *server.Server {
	s := server.New(b)
	s.Addr = addr
	// v1 ignores extensions advertising built-in IDLE during registration.
	// Register selection hooks first, then enable our polling IDLE override.
	ext := &selectionExtension{}
	s.Enable(ext)
	ext.ready = true
	s.AllowInsecureAuth = false
	s.AutoLogout = 30 * time.Minute
	s.MaxLiteralSize = 25 * 1024 * 1024
	s.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		c, e := tls.LoadX509KeyPair(cert, key)
		return &c, e
	}}
	return s
}

var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("imap-unknown-account"), bcrypt.DefaultCost)

func (b *Backend) Login(info *imap.ConnInfo, address, password string) (backend.User, error) {
	if info == nil || info.TLS == nil {
		return nil, backend.ErrInvalidCredentials
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	address = strings.ToLower(strings.TrimSpace(address))
	if b.limiter != nil {
		host, _, _ := net.SplitHostPort(info.RemoteAddr.String())
		if !b.limiter.Allow(ctx, ratelimit.Rule{Name: "imap-login", Limit: 30, Window: time.Minute}, host).Allowed {
			return nil, backend.ErrInvalidCredentials
		}
	}
	var userID, boxID, hash string
	err := b.pool.QueryRow(ctx, `SELECT wm.user_id,m.id,i.password_hash FROM mailboxes m JOIN domains d ON d.id=m.domain_id
 JOIN workspaces w ON w.id=coalesce(m.personal_workspace_id,d.workspace_id)
 JOIN workspace_members wm ON wm.workspace_id=w.id AND wm.user_id=coalesce(m.owner_user_id,w.personal_owner_id)
 JOIN identities i ON i.user_id=wm.user_id AND i.provider='password'
 WHERE lower(m.local_part || '@' || d.domain)=$1 AND d.verified_at IS NOT NULL`, address).Scan(&userID, &boxID, &hash)
	if err != nil {
		bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return nil, backend.ErrInvalidCredentials
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return nil, backend.ErrInvalidCredentials
	}
	return &User{b: b, id: userID, box: boxID, address: address, passwordHash: hash}, nil
}

type User struct {
	b                              *Backend
	id, box, address, passwordHash string
}

func (u *User) Username() string { return u.address }
func (u *User) Logout() error    { return nil }
func (u *User) check(ctx context.Context) error {
	allowed, err := u.b.access.CanAccess(ctx, u.id, u.box)
	if err != nil {
		return err
	}
	if !allowed {
		return backend.ErrInvalidCredentials
	}
	// Removal, reassignment, domain suspension and password changes revoke existing connections.
	var active bool
	err = u.b.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mailboxes m JOIN domains d ON d.id=m.domain_id JOIN workspaces w ON w.id=coalesce(m.personal_workspace_id,d.workspace_id) JOIN identities i ON i.user_id=$2 AND i.provider='password' WHERE m.id=$1 AND coalesce(m.owner_user_id,w.personal_owner_id)=$2 AND d.verified_at IS NOT NULL AND i.password_hash=$3)`, u.box, u.id, u.passwordHash).Scan(&active)
	if err != nil {
		return err
	}
	if !active {
		return backend.ErrInvalidCredentials
	}
	return nil
}
func canonical(name string) string {
	if strings.EqualFold(name, "INBOX") {
		return "INBOX"
	}
	return name
}
func validFolder(name string) bool {
	return name != "" && len(name) <= 200 && !strings.ContainsAny(name, "\r\n\x00") && !strings.Contains(name, "/")
}
func (u *User) ListMailboxes(subscribed bool) ([]backend.Mailbox, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := u.check(ctx); err != nil {
		return nil, err
	}
	rows, err := u.b.pool.Query(ctx, `SELECT name FROM imap_folders WHERE mailbox_id=$1 AND (NOT $2 OR subscribed) ORDER BY name`, u.box, subscribed)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []backend.Mailbox{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, &Mailbox{u: u, name: name})
	}
	return out, rows.Err()
}
func (u *User) GetMailbox(name string) (backend.Mailbox, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := u.check(ctx); err != nil {
		return nil, err
	}
	name = canonical(name)
	var exists bool
	err := u.b.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM imap_folders WHERE mailbox_id=$1 AND name=$2)`, u.box, name).Scan(&exists)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, backend.ErrNoSuchMailbox
	}
	return &Mailbox{u: u, name: name}, nil
}
func (u *User) CreateMailbox(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := u.check(ctx); err != nil {
		return err
	}
	name = canonical(name)
	if !validFolder(name) {
		return errors.New("invalid folder name (flat folders only)")
	}
	result, err := u.b.pool.Exec(ctx, `INSERT INTO imap_folders(mailbox_id,name) VALUES($1,$2) ON CONFLICT DO NOTHING`, u.box, name)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return backend.ErrMailboxAlreadyExists
	}
	return nil
}
func (u *User) DeleteMailbox(name string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := u.check(ctx); err != nil {
		return err
	}
	name = canonical(name)
	if name == "INBOX" {
		return errors.New("INBOX cannot be deleted")
	}
	result, err := u.b.pool.Exec(ctx, `DELETE FROM imap_folders WHERE mailbox_id=$1 AND name=$2`, u.box, name)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return backend.ErrNoSuchMailbox
	}
	return nil
}
func (u *User) RenameMailbox(old, new string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := u.check(ctx); err != nil {
		return err
	}
	old = canonical(old)
	new = canonical(new)
	if !validFolder(new) || new == "INBOX" {
		return errors.New("invalid destination")
	}
	tx, err := u.b.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if old == "INBOX" {
		if _, err = tx.Exec(ctx, `INSERT INTO imap_folders(mailbox_id,name) VALUES($1,$2)`, u.box, new); err != nil {
			return backend.ErrMailboxAlreadyExists
		}
		_, err = tx.Exec(ctx, `UPDATE messages SET folder=$2 WHERE mailbox_id=$1 AND folder='INBOX'`, u.box, new)
	} else {
		result, e := tx.Exec(ctx, `UPDATE imap_folders SET name=$3 WHERE mailbox_id=$1 AND name=$2`, u.box, old, new)
		err = e
		if e == nil && result.RowsAffected() == 0 {
			return backend.ErrNoSuchMailbox
		}
	}
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// append imports through the same MIME parser as LMTP, while excluding the
// SMTP retry-deduplication index. Limits apply before buffering client input.
func (u *User) append(ctx context.Context, folder string, flags []string, date time.Time, body io.Reader) error {
	if err := u.check(ctx); err != nil {
		return err
	}
	raw, err := io.ReadAll(io.LimitReader(body, 25*1024*1024+1))
	if err != nil {
		return err
	}
	if len(raw) == 0 || len(raw) > 25*1024*1024 {
		return errors.New("message exceeds size limit")
	}
	return u.b.access.AppendIMAP(ctx, u.box, folder, raw, flags, date)
}
