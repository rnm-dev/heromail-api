// Package smtp implements provider.Sender on top of SMTP.
package smtp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rnm/heromail/backend/internal/provider"
	"github.com/wneessen/go-mail"
)

// Sender delivers mail over SMTP. The zero value is not usable; build one with
// New or NewFromEnv.
type Sender struct {
	host     string
	port     int
	username string
	password string
	timeout  time.Duration

	// tls controls whether STARTTLS is required, attempted, or skipped. Dev
	// runs against Mailpit, which speaks plaintext.
	tls mail.TLSPolicy

	// helo is the name we greet the receiving server with. Empty means
	// go-mail's default, os.Hostname().
	helo string
}

// Config is the knob set for New.
type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	Timeout  time.Duration
	// RequireTLS demands STARTTLS and fails if the server does not offer it.
	// Leave false for local Mailpit; set it for any real relay.
	RequireTLS bool

	// HELO is the name announced in the EHLO greeting. It must be a FQDN that
	// resolves to the sending IP, and it should match that IP's PTR — receivers
	// check all three agree, and a bare hostname like "nid-01" (go-mail's
	// default, from os.Hostname) fails every one of those checks.
	//
	// Empty is fine for Mailpit, which does not care.
	HELO string
}

func New(cfg Config) (*Sender, error) {
	if strings.TrimSpace(cfg.Host) == "" {
		return nil, fmt.Errorf("smtp: host is empty")
	}
	if cfg.Port <= 0 {
		return nil, fmt.Errorf("smtp: invalid port %d", cfg.Port)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}

	policy := mail.NoTLS
	if cfg.RequireTLS {
		policy = mail.TLSMandatory
	}

	return &Sender{
		host:     cfg.Host,
		port:     cfg.Port,
		username: cfg.Username,
		password: cfg.Password,
		timeout:  cfg.Timeout,
		tls:      policy,
		helo:     strings.TrimSpace(cfg.HELO),
	}, nil
}

// NewFromEnv builds a Sender from SMTP_HOST and SMTP_PORT, with optional
// SMTP_USERNAME / SMTP_PASSWORD and SMTP_REQUIRE_TLS.
func NewFromEnv() (*Sender, error) {
	host := os.Getenv("SMTP_HOST")
	portStr := os.Getenv("SMTP_PORT")
	if portStr == "" {
		portStr = "25"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("smtp: SMTP_PORT %q is not a number: %w", portStr, err)
	}

	return New(Config{
		Host:       host,
		Port:       port,
		Username:   os.Getenv("SMTP_USERNAME"),
		Password:   os.Getenv("SMTP_PASSWORD"),
		RequireTLS: os.Getenv("SMTP_REQUIRE_TLS") == "1",
		HELO:       os.Getenv("SMTP_HELO"),
	})
}

// Send delivers msg and returns the Message-ID it was sent under.
//
// SMTP gives no portable way to learn a server-side identifier: the 250 reply
// carries a queue id in a format each MTA invents for itself, and it is lost
// the moment the message leaves that hop. So we generate the Message-ID
// ourselves and return that. It travels with the message, and bounce reports
// quote it back (RFC 5321 requires the original headers in the DSN), which is
// exactly what email_events needs to correlate against.
func (s *Sender) Send(ctx context.Context, msg provider.Message) (string, error) {
	if err := msg.Validate(); err != nil {
		return "", err
	}

	messageID, err := newMessageID(msg.From)
	if err != nil {
		return "", fmt.Errorf("smtp: generate message id: %w", err)
	}

	m := mail.NewMsg()
	if err := m.From(msg.From); err != nil {
		return "", fmt.Errorf("%w: From %q: %v", provider.ErrInvalidMessage, msg.From, err)
	}
	if err := m.To(msg.To...); err != nil {
		return "", fmt.Errorf("%w: To %v: %v", provider.ErrInvalidMessage, msg.To, err)
	}
	m.Subject(msg.Subject)
	m.SetMessageIDWithValue(messageID)

	// Caller headers are applied before the bodies so a caller cannot clobber
	// Content-Type or the Message-ID we just committed to returning.
	for k, v := range msg.Headers {
		switch strings.ToLower(k) {
		case "message-id", "content-type", "mime-version", "from", "to", "subject":
			return "", fmt.Errorf("%w: header %q is set by the sender", provider.ErrInvalidMessage, k)
		}
		m.SetGenHeader(mail.Header(k), v)
	}

	// A text part plus an HTML alternative is what every client expects; when
	// only one body is present, send that single part rather than an
	// alternative with an empty half.
	switch {
	case msg.TextBody != "" && msg.HTMLBody != "":
		m.SetBodyString(mail.TypeTextPlain, msg.TextBody)
		m.AddAlternativeString(mail.TypeTextHTML, msg.HTMLBody)
	case msg.HTMLBody != "":
		m.SetBodyString(mail.TypeTextHTML, msg.HTMLBody)
	default:
		m.SetBodyString(mail.TypeTextPlain, msg.TextBody)
	}

	for _, a := range msg.Attachments {
		if err := m.AttachReader(a.Filename, a.Content, mail.WithFileContentType(mail.ContentType(a.ContentType))); err != nil {
			return "", fmt.Errorf("%w: attach %q: %v", provider.ErrInvalidMessage, a.Filename, err)
		}
	}

	if msg.DKIM != nil {
		signer, err := dkimSigner(*msg.DKIM)
		if err != nil {
			// A key that fails to parse is our fault, not a transport problem,
			// but it must still not go out silently unsigned — the caller
			// asked for a signature it will not get.
			return "", fmt.Errorf("smtp: DKIM signer for %s: %w", msg.DKIM.Domain, err)
		}
		m.SetDKIM(signer)
	}

	opts := []mail.Option{
		mail.WithPort(s.port),
		mail.WithTLSPolicy(s.tls),
		mail.WithTimeout(s.timeout),
	}
	if s.helo != "" {
		opts = append(opts, mail.WithHELO(s.helo))
	}
	if s.username != "" {
		opts = append(opts,
			mail.WithSMTPAuth(mail.SMTPAuthPlain),
			mail.WithUsername(s.username),
			mail.WithPassword(s.password),
		)
	}

	client, err := mail.NewClient(s.host, opts...)
	if err != nil {
		return "", fmt.Errorf("smtp: build client: %w", err)
	}
	if err := client.DialAndSendWithContext(ctx, m); err != nil {
		return "", fmt.Errorf("smtp: send to %s:%d: %w", s.host, s.port, err)
	}

	return messageID, nil
}

// newMessageID returns a globally unique id of the form "<random>@<domain>",
// where the domain is taken from the sender so the id looks like it belongs to
// the workspace that sent it.
func newMessageID(from string) (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}

	domain := "heromail.local"
	if at := strings.LastIndex(from, "@"); at >= 0 && at+1 < len(from) {
		domain = strings.Trim(from[at+1:], "<> ")
	}

	return hex.EncodeToString(raw) + "@" + domain, nil
}

// dkimSigner builds a go-mail DKIM signer from a PKCS#8-encoded RSA private
// key. Relaxed/relaxed canonicalization is what almost every real-world
// setup uses — "simple" breaks the moment a relay so much as re-wraps a
// header line, which is common and not something we control once the
// message leaves us.
func dkimSigner(d provider.DKIM) (*mail.DKIMSigner, error) {
	key, err := x509.ParsePKCS8PrivateKey(d.PrivateKeyDER)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is %T, not RSA", key)
	}

	signer := mail.NewDKIMSigner(d.Domain, d.Selector, rsaKey)
	signer.HeaderCanonicalization(mail.CanonicalizationRelaxed)
	signer.BodyCanonicalization(mail.CanonicalizationRelaxed)
	return signer, nil
}

// Compile-time proof that Sender satisfies the interface.
var _ provider.Sender = (*Sender)(nil)
