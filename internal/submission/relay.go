package submission

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/rnm/heromail/backend/internal/maildomain"
	mail "github.com/wneessen/go-mail"
)

func DKIM(domains *maildomain.Service) Sign {
	return func(ctx context.Context, workspace, domain string, raw []byte) ([]byte, error) {
		selector, der, err := domains.SigningKeyForDomain(ctx, workspace, domain)
		if err != nil {
			return nil, err
		}
		key, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, err
		}
		private, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("invalid signing key")
		}
		signer := mail.NewDKIMSigner(domain, selector, private)
		signer.HeaderCanonicalization(mail.CanonicalizationRelaxed)
		signer.BodyCanonicalization(mail.CanonicalizationRelaxed)
		signer.OversignHeaders("From", "Sender")
		i := bytes.Index(raw, []byte("\r\n\r\n"))
		if i < 0 {
			return nil, fmt.Errorf("missing header separator")
		}
		signature, err := signer.Sign(raw[:i+2], raw[i+4:])
		if err != nil {
			return nil, err
		}
		return append([]byte(signature), raw...), nil
	}
}

// SMTPRelay hands the complete original MIME message to the trusted local Postfix
// queue. A success means Postfix accepted DATA; it owns delivery and retries.
func SMTPRelay(addr, hello string) Relay {
	return func(ctx context.Context, from string, to []string, raw []byte) error {
		conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return err
		}
		defer conn.Close()
		deadline := time.Now().Add(35 * time.Second)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		conn.SetDeadline(deadline)
		c := smtp.NewClient(conn)
		defer c.Close()
		if err = c.Hello(hello); err != nil {
			return err
		}
		if err = c.SendMail(from, to, bytes.NewReader(raw)); err != nil {
			return err
		}
		// QUIT failure after DATA success must not make the client resend the message.
		_ = c.Quit()
		return nil
	}
}
