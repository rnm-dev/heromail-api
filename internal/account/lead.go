package account

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"github.com/rnm/heromail/backend/internal/provider"
)

// ErrLeadsDisabled means no address is configured to receive leads.
var ErrLeadsDisabled = errors.New("account: leads are not configured")

// Lead is a request from the landing form to connect a company.
type Lead struct {
	Name      string
	Email     string
	Company   string
	Domain    string
	Mailboxes string
	Message   string
	// IP and UserAgent help tell a person from a script when reading the mail.
	IP        string
	UserAgent string
}

// leadLimits are the longest values accepted, in characters.
const (
	leadNameMax    = 120
	leadCompanyMax = 160
	leadDomainMax  = 253
	leadMessageMax = 2000
)

var leadMailboxes = map[string]bool{"": true, "1-10": true, "11-50": true, "51-200": true, "200+": true}

// normalise trims the lead and rejects what cannot be answered. Single-line
// fields lose their line breaks: two of them end up in mail headers.
func (l *Lead) normalise() error {
	l.Name = oneLine(l.Name)
	l.Company = oneLine(l.Company)
	l.Domain = strings.ToLower(oneLine(l.Domain))
	l.Mailboxes = strings.TrimSpace(l.Mailboxes)
	l.Message = strings.TrimSpace(l.Message)
	l.Email = strings.TrimSpace(l.Email)

	switch {
	case l.Name == "":
		return fmt.Errorf("%w: name is required", ErrValidation)
	case len([]rune(l.Name)) > leadNameMax:
		return fmt.Errorf("%w: name is too long", ErrValidation)
	case len([]rune(l.Company)) > leadCompanyMax:
		return fmt.Errorf("%w: company is too long", ErrValidation)
	case len([]rune(l.Domain)) > leadDomainMax:
		return fmt.Errorf("%w: domain is too long", ErrValidation)
	case len([]rune(l.Message)) > leadMessageMax:
		return fmt.Errorf("%w: message is too long", ErrValidation)
	case !leadMailboxes[l.Mailboxes]:
		return fmt.Errorf("%w: mailboxes must be one of 1-10, 11-50, 51-200, 200+", ErrValidation)
	}
	addr, err := mail.ParseAddress(l.Email)
	if err != nil || addr.Address != l.Email || strings.ContainsAny(l.Email, "\r\n") {
		return fmt.Errorf("%w: email must be a valid address", ErrValidation)
	}
	return nil
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// LeadsTo is the address leads are emailed to, empty when the form is off.
func (s *Service) LeadsTo() string { return s.cfg.LeadsTo }

// SendLead emails the request to the sales address. Unlike the account mail it
// is not best-effort: nothing else keeps the lead, so a failed hand-over is
// returned and the page falls back to the direct address.
func (s *Service) SendLead(ctx context.Context, lead Lead) error {
	if err := lead.normalise(); err != nil {
		return err
	}
	if s.cfg.LeadsTo == "" {
		return ErrLeadsDisabled
	}

	who := lead.Company
	if who == "" {
		who = lead.Domain
	}
	if who == "" {
		who = lead.Name
	}

	var b strings.Builder
	b.WriteString("Заявка на подключение компании с сайта Heromail.\n\n")
	row := func(label, value string) {
		if value != "" {
			fmt.Fprintf(&b, "%s: %s\n", label, value)
		}
	}
	row("Имя", lead.Name)
	row("Email", lead.Email)
	row("Компания", lead.Company)
	row("Домен", lead.Domain)
	row("Ящиков", lead.Mailboxes)
	if lead.Message != "" {
		fmt.Fprintf(&b, "\nКомментарий:\n%s\n", lead.Message)
	}
	b.WriteString("\nОтветьте на это письмо — ответ уйдёт автору заявки.\n")
	fmt.Fprintf(&b, "\n--\nIP: %s\nБраузер: %s\n", lead.IP, oneLine(lead.UserAgent))

	_, err := s.sender.Send(ctx, provider.Message{
		DKIM:     s.signMailFrom(ctx),
		From:     s.cfg.MailFrom,
		To:       []string{s.cfg.LeadsTo},
		Subject:  "Заявка на подключение: " + who,
		TextBody: b.String(),
		Headers:  map[string]string{"Reply-To": lead.Email},
	})
	if err != nil {
		return fmt.Errorf("account: send lead: %w", err)
	}
	return nil
}
