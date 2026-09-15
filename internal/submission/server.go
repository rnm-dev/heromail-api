// Package submission implements authenticated client SMTP with mailbox ownership enforcement.
package submission

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/mail"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rnm/heromail/backend/internal/inbound"
	"github.com/rnm/heromail/backend/internal/ratelimit"
	"golang.org/x/crypto/bcrypt"
)

type Relay func(context.Context, string, []string, []byte) error
type Sign func(context.Context, string, string, []byte) ([]byte, error)
type Backend struct {
	Pool        *pgxpool.Pool
	Limiter     *ratelimit.Limiter
	Relay       Relay
	Sign        Sign
	Minute, Day int
}

func Server(b *Backend, addr, cert, key string) *smtp.Server {
	s := smtp.NewServer(b)
	s.Addr = addr
	s.Domain = "mail.heromail.kz"
	s.ReadTimeout = 60 * time.Second
	s.WriteTimeout = 60 * time.Second
	s.MaxMessageBytes = inbound.MaxMessageBytes
	s.MaxRecipients = 50
	s.AllowInsecureAuth = false
	s.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		c, e := tls.LoadX509KeyPair(cert, key)
		return &c, e
	}}
	return s
}
func (b *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) { return &session{b: b, c: c}, nil }

type session struct {
	b                                         *Backend
	c                                         *smtp.Conn
	user, box, workspace, address, hash, from string
	recipients                                []string
	applicationCredential                     bool
}

var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("submission-unknown-user"), bcrypt.DefaultCost)
var authRequired = &smtp.SMTPError{Code: 530, EnhancedCode: smtp.EnhancedCode{5, 7, 0}, Message: "Authentication required"}

func temporary() error {
	return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "Temporary submission failure; retry later"}
}
func denied() error {
	return &smtp.SMTPError{Code: 553, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "Sender must match authenticated mailbox"}
}

const identityQuery = `SELECT wm.user_id,m.id,w.id,i.password_hash FROM mailboxes m JOIN domains d ON d.id=m.domain_id
 JOIN workspaces w ON w.id=coalesce(m.personal_workspace_id,d.workspace_id)
 JOIN workspace_members wm ON wm.workspace_id=w.id AND wm.user_id=coalesce(m.owner_user_id,w.personal_owner_id)
 JOIN users u ON u.id=wm.user_id JOIN identities i ON i.user_id=u.id AND i.provider='password'
 WHERE lower(m.local_part||'@'||d.domain)=$1 AND d.verified_at IS NOT NULL AND NOT u.must_change_password`

// A mailbox password delegates sending only. Its issuer must still own the
// workspace; assignment and membership changes revoke the stored credential.
const mailboxCredentialQuery = `SELECT c.issued_by,m.id,w.id,c.password_hash
 FROM mailbox_smtp_credentials c JOIN mailboxes m ON m.id=c.mailbox_id
 JOIN domains d ON d.id=m.domain_id JOIN workspaces w ON w.id=coalesce(m.personal_workspace_id,d.workspace_id)
 JOIN workspace_members wm ON wm.workspace_id=w.id AND wm.user_id=c.issued_by AND wm.role='owner'
 WHERE lower(m.local_part||'@'||d.domain)=$1 AND d.verified_at IS NOT NULL`

func (s *session) AuthMechanisms() []string { return []string{sasl.Plain} }
func (s *session) Auth(mech string) (sasl.Server, error) {
	if _, ok := s.c.TLSConnectionState(); !ok {
		return nil, authRequired
	}
	if mech != sasl.Plain {
		return nil, smtp.ErrAuthUnknownMechanism
	}
	return sasl.NewPlainServer(func(identity, address, password string) error {
		address = strings.ToLower(strings.TrimSpace(address))
		if identity != "" && !strings.EqualFold(identity, address) {
			return smtp.ErrAuthFailed
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if s.b.Limiter != nil {
			host, _, _ := net.SplitHostPort(s.c.Conn().RemoteAddr().String())
			if !s.b.Limiter.AllowStrict(ctx, ratelimit.Rule{Name: "submission:login:ip", Limit: 30, Window: time.Minute}, host).Allowed || !s.b.Limiter.AllowStrict(ctx, ratelimit.Rule{Name: "submission:login:address", Limit: 30, Window: 15 * time.Minute}, address).Allowed {
				return smtp.ErrAuthFailed
			}
		}
		var user, box, ws, hash string
		authenticated := false
		application := false
		for _, candidate := range []struct {
			query       string
			application bool
		}{{mailboxCredentialQuery, true}, {identityQuery, false}} {
			err := s.b.Pool.QueryRow(ctx, candidate.query, address).Scan(&user, &box, &ws, &hash)
			if err != nil {
				bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
				continue
			}
			if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil {
				authenticated = true
				application = candidate.application
				break
			}
		}
		if !authenticated {
			return smtp.ErrAuthFailed
		}
		s.applicationCredential = application
		s.user = user
		s.box = box
		s.workspace = ws
		s.hash = hash
		s.address = address
		return nil
	}), nil
}
func (s *session) check(ctx context.Context) error {
	if s.user == "" {
		return authRequired
	}
	var user, box, ws, hash string
	query := identityQuery
	if s.applicationCredential {
		query = mailboxCredentialQuery
	}
	if err := s.b.Pool.QueryRow(ctx, query, s.address).Scan(&user, &box, &ws, &hash); err != nil {
		return smtp.ErrAuthFailed
	}
	if user != s.user || box != s.box || ws != s.workspace || hash != s.hash {
		return smtp.ErrAuthFailed
	}
	return nil
}
func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.check(ctx); err != nil {
		return err
	}
	if !strings.EqualFold(from, s.address) {
		return denied()
	}
	s.from = s.address
	s.recipients = nil
	return nil
}
func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	if s.user == "" || s.from == "" {
		return authRequired
	}
	a, err := mail.ParseAddress(to)
	if err != nil || a.Address != to || strings.ContainsAny(to, "\r\n\x00") {
		return &smtp.SMTPError{Code: 553, Message: "Invalid recipient"}
	}
	s.recipients = append(s.recipients, to)
	return nil
}
func (s *session) Data(r io.Reader) error {
	raw, err := io.ReadAll(io.LimitReader(r, inbound.MaxMessageBytes+1))
	if err != nil {
		return temporary()
	}
	if len(raw) > inbound.MaxMessageBytes {
		return &smtp.SMTPError{Code: 552, Message: "Message too large"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err = s.check(ctx); err != nil {
		return err
	}
	if s.from == "" || len(s.recipients) == 0 {
		return authRequired
	}
	raw, err = prepare(raw, s.address)
	if err != nil {
		return denied()
	}
	if s.b.Limiter != nil {
		minute, day := s.b.Minute, s.b.Day
		if minute <= 0 {
			minute = 60
		}
		if day <= 0 {
			day = 5000
		}
		for _, rule := range []ratelimit.Rule{{Name: "send:minute", Limit: minute, Window: time.Minute}, {Name: "send:day", Limit: day, Window: 24 * time.Hour}} {
			if !s.b.Limiter.AllowStrict(ctx, rule, s.workspace).Allowed {
				return &smtp.SMTPError{Code: 451, Message: "Submission quota exceeded; retry later"}
			}
		}
	}
	raw, err = s.b.Sign(ctx, s.workspace, strings.SplitN(s.address, "@", 2)[1], raw)
	if err != nil {
		log.Printf("submission signing: %v", err)
		return temporary()
	}
	// Recheck after signing so password/ownership revocation applies to this transaction.
	if err = s.check(ctx); err != nil {
		return err
	}
	if err = s.b.Relay(ctx, s.from, s.recipients, raw); err != nil {
		log.Printf("submission relay: %v", err)
		var upstream *smtp.SMTPError
		if errors.As(err, &upstream) && upstream.Code >= 500 {
			return &smtp.SMTPError{Code: 554, Message: "Relay rejected message"}
		}
		return temporary()
	}
	log.Printf("submission accepted mailbox=%s recipients=%d bytes=%d", s.box, len(s.recipients), len(raw))
	return nil
}
func (s *session) Reset()        { s.from = ""; s.recipients = nil }
func (s *session) Logout() error { return nil }

// Preserve MIME bytes; remove client-supplied blind-recipient and transport headers.
// Reject ambiguous author headers rather than letting another client interpret them differently.
func prepare(raw []byte, address string) ([]byte, error) {
	split := bytes.Index(raw, []byte("\r\n\r\n"))
	if split < 0 || split > 128*1024 {
		return nil, errors.New("invalid headers")
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	for _, key := range []string{"From", "Sender"} {
		values := msg.Header[key]
		if key == "From" && len(values) != 1 {
			return nil, denied()
		}
		if len(values) > 1 {
			return nil, denied()
		}
		if len(values) == 1 {
			list, e := mail.ParseAddressList(values[0])
			if e != nil || len(list) != 1 || !strings.EqualFold(list[0].Address, address) {
				return nil, denied()
			}
		}
	}
	var out bytes.Buffer
	if len(msg.Header["Date"]) > 1 || len(msg.Header["Message-Id"]) > 1 {
		return nil, denied()
	}
	if msg.Header.Get("Date") == "" {
		out.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n")
	}
	if msg.Header.Get("Message-ID") == "" {
		out.WriteString("Message-ID: <" + uuid.NewString() + "@" + strings.SplitN(address, "@", 2)[1] + ">\r\n")
	}
	skip := false
	for _, line := range bytes.Split(raw[:split], []byte("\r\n")) {
		if len(line) == 0 {
			return nil, denied()
		}
		if line[0] != ' ' && line[0] != '\t' {
			i := bytes.IndexByte(line, ':')
			if i <= 0 {
				return nil, denied()
			}
			name := strings.ToLower(string(line[:i]))
			if strings.HasPrefix(name, "resent-") {
				return nil, denied()
			}
			skip = name == "bcc" || name == "return-path" || name == "received" || name == "authentication-results" || name == "dkim-signature" || strings.HasPrefix(name, "arc-")
		}
		if !skip {
			out.Write(line)
			out.WriteString("\r\n")
		}
	}
	out.WriteString("\r\n")
	out.Write(raw[split+4:])
	return out.Bytes(), nil
}
