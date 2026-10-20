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
	"github.com/rnm/heromail/backend/internal/mailauth"
	"github.com/rnm/heromail/backend/internal/ratelimit"
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
	b             *Backend
	c             *smtp.Conn
	principal     mailauth.Principal
	address, from string
	recipients    []string
}

var authRequired = &smtp.SMTPError{Code: 530, EnhancedCode: smtp.EnhancedCode{5, 7, 0}, Message: "Authentication required"}

func temporary() error {
	return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "Temporary submission failure; retry later"}
}
func denied() error {
	return &smtp.SMTPError{Code: 553, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "Sender must match authenticated mailbox"}
}

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
		host, _, _ := net.SplitHostPort(s.c.Conn().RemoteAddr().String())
		if !mailauth.Allow(ctx, s.b.Limiter, "submission", host, address) {
			return smtp.ErrAuthFailed
		}
		p, ok := mailauth.Login(ctx, s.b.Pool, address, password, mailauth.Application, mailauth.Account)
		if !ok {
			return smtp.ErrAuthFailed
		}
		s.principal = p
		s.address = address
		return nil
	}), nil
}
func (s *session) check(ctx context.Context) error {
	if s.principal.UserID == "" {
		return authRequired
	}
	// Re-resolve so removal, reassignment and password changes end the session.
	if current, err := mailauth.Lookup(ctx, s.b.Pool, s.address, s.principal.Kind); err != nil || current != s.principal {
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
	if s.principal.UserID == "" || s.from == "" {
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
			if !s.b.Limiter.AllowStrict(ctx, rule, s.principal.WorkspaceID).Allowed {
				return &smtp.SMTPError{Code: 451, Message: "Submission quota exceeded; retry later"}
			}
		}
	}
	raw, err = s.b.Sign(ctx, s.principal.WorkspaceID, strings.SplitN(s.address, "@", 2)[1], raw)
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
	log.Printf("submission accepted mailbox=%s recipients=%d bytes=%d", s.principal.MailboxID, len(s.recipients), len(raw))
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
