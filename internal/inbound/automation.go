package inbound

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/mail"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrAutomationConflict = errors.New("settings changed; reload before saving")
var ErrAutomationValidation = errors.New("invalid automation settings")

type MailRule struct {
	Name      string  `json:"name"`
	Enabled   bool    `json:"enabled"`
	From      string  `json:"from"`
	Subject   string  `json:"subject"`
	Category  string  `json:"category,omitempty"`
	FolderUID *int64  `json:"folder_uidvalidity,omitempty"`
	LabelID   *string `json:"label_id,omitempty"`
	MarkRead  bool    `json:"mark_read"`
	Stop      bool    `json:"stop"`
}
type Vacation struct {
	Enabled bool       `json:"enabled"`
	Subject string     `json:"subject"`
	Text    string     `json:"text"`
	Start   *time.Time `json:"start,omitempty"`
	End     *time.Time `json:"end,omitempty"`
}
type Automation struct {
	PendingReplies int        `json:"pending_replies"`
	FailedReplies  int        `json:"failed_replies"`
	Version        int        `json:"version"`
	Rules          []MailRule `json:"rules"`
	Vacation       Vacation   `json:"vacation"`
}

func (v Vacation) Active(now time.Time) bool {
	return v.Enabled && (v.Start == nil || !now.Before(*v.Start)) && (v.End == nil || now.Before(*v.End))
}
func readAutomation(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, box string, lock bool) (Automation, error) {
	out := Automation{Rules: []MailRule{}}
	var raw []byte
	sql := `SELECT version,config FROM mailbox_automation WHERE mailbox_id=$1`
	if lock {
		sql += " FOR SHARE"
	}
	err := q.QueryRow(ctx, sql, box).Scan(&out.Version, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	version := out.Version
	err = json.Unmarshal(raw, &out)
	out.Version = version
	if out.Rules == nil {
		out.Rules = []MailRule{}
	}
	return out, err
}
func (s *Store) GetAutomation(ctx context.Context, box string) (Automation, error) {
	a, err := readAutomation(ctx, s.pool, box, false)
	if err != nil {
		return a, err
	}
	err = s.pool.QueryRow(ctx, `SELECT count(*) FILTER(WHERE j.status='pending'),count(*) FILTER(WHERE j.status='dead' OR e.status IN ('failed','dead')) FROM vacation_jobs j LEFT JOIN emails e ON e.id=j.email_id WHERE j.mailbox_id=$1`, box).Scan(&a.PendingReplies, &a.FailedReplies)
	return a, err
}
func validateAutomation(a Automation) error {
	invalid := func(s string) error { return fmt.Errorf("%w: %s", ErrAutomationValidation, s) }
	if a.Version < 0 || len(a.Rules) > 50 {
		return invalid("maximum 50 rules")
	}
	for _, r := range a.Rules {
		if strings.TrimSpace(r.Name) == "" || utf8.RuneCountInString(r.Name) > 80 || strings.IndexFunc(r.Name, unicode.IsControl) >= 0 {
			return invalid("rule name: 1–80 characters")
		}
		if r.From != "" {
			addr, err := mail.ParseAddress(r.From)
			if err != nil || addr.Address != r.From || len(r.From) > 320 {
				return invalid("sender must be a plain email address")
			}
		}
		if len(r.Subject) > 500 || strings.IndexFunc(r.Subject, unicode.IsControl) >= 0 {
			return invalid("subject condition is too long or contains control characters")
		}
		if r.Category != "" && !ValidCategory(r.Category) {
			return invalid("unknown category")
		}
		if r.From == "" && strings.TrimSpace(r.Subject) == "" && r.Category == "" {
			return invalid("specify sender, subject or category")
		}
		if r.FolderUID == nil && r.LabelID == nil && !r.MarkRead {
			return invalid("choose an action")
		}
		if r.LabelID != nil {
			if _, err := uuid.Parse(*r.LabelID); err != nil {
				return invalid("invalid label")
			}
		}
	}
	v := a.Vacation
	if len(v.Subject) > 200 || strings.IndexFunc(v.Subject, unicode.IsControl) >= 0 || len(v.Text) > 10000 {
		return invalid("reply subject: 200 bytes; body: 10000 bytes")
	}
	if v.Enabled && (strings.TrimSpace(v.Subject) == "" || strings.TrimSpace(v.Text) == "") {
		return invalid("reply subject and text are required")
	}
	if v.Start != nil && v.End != nil && !v.Start.Before(*v.End) {
		return invalid("end must follow start")
	}
	return nil
}
func (s *Store) SaveAutomation(ctx context.Context, box string, a Automation) (Automation, error) {
	if err := validateAutomation(a); err != nil {
		return a, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return a, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, box); err != nil {
		return a, err
	}
	old, err := readAutomation(ctx, tx, box, false)
	if err != nil {
		return a, err
	}
	if old.Version != a.Version {
		return a, ErrAutomationConflict
	}
	for _, r := range a.Rules {
		if !r.Enabled {
			continue
		}
		var valid bool
		if r.FolderUID != nil {
			err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM imap_folders WHERE mailbox_id=$1 AND uidvalidity=$2)`, box, *r.FolderUID).Scan(&valid)
			if err != nil {
				return a, err
			}
			if !valid {
				return a, fmt.Errorf("%w: folder no longer exists", ErrAutomationValidation)
			}
		}
		if r.LabelID != nil {
			err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mail_labels WHERE mailbox_id=$1 AND id=$2)`, box, *r.LabelID).Scan(&valid)
			if err != nil {
				return a, err
			}
			if !valid {
				return a, fmt.Errorf("%w: label no longer exists", ErrAutomationValidation)
			}
		}
	}
	a.Version++
	a.PendingReplies = 0
	a.FailedReplies = 0
	if a.Rules == nil {
		a.Rules = []MailRule{}
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return a, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO mailbox_automation(mailbox_id,version,config) VALUES($1,$2,$3) ON CONFLICT(mailbox_id) DO UPDATE SET version=$2,config=$3,updated_at=now()`, box, a.Version, raw)
	if err != nil {
		return a, err
	}
	if err = tx.Commit(ctx); err != nil {
		return a, err
	}
	return a, nil
}

// Called only for a newly inserted LMTP message, inside its delivery transaction.
func (s *Store) automate(ctx context.Context, tx pgx.Tx, p DeliverParams, m *Message) error {
	if m.Folder == "Junk" {
		return nil
	}
	a, err := readAutomation(ctx, tx, p.MailboxID, false)
	if err != nil {
		return err
	}
	if a.Version == 0 {
		return nil
	}
	from, subject := "", ""
	if m.FromAddr != nil {
		from = *m.FromAddr
	}
	subject = m.Subject
	for _, r := range a.Rules {
		if !r.Enabled || r.From != "" && !strings.EqualFold(r.From, from) || !strings.Contains(strings.ToLower(subject), strings.ToLower(r.Subject)) || r.Category != "" && r.Category != m.Category {
			continue
		}
		// Missing targets make this rule inert rather than losing incoming mail.
		folder := m.Folder
		if r.FolderUID != nil {
			err = tx.QueryRow(ctx, `SELECT name FROM imap_folders WHERE mailbox_id=$1 AND uidvalidity=$2 FOR KEY SHARE`, p.MailboxID, *r.FolderUID).Scan(&folder)
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
		}
		if r.LabelID != nil {
			var id string
			err = tx.QueryRow(ctx, `SELECT id FROM mail_labels WHERE mailbox_id=$1 AND id=$2 FOR KEY SHARE`, p.MailboxID, *r.LabelID).Scan(&id)
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, `INSERT INTO message_labels(mailbox_id,message_id,label_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, p.MailboxID, m.ID, id); err != nil {
				return err
			}
		}
		m, err = scanMessage(tx.QueryRow(ctx, `UPDATE messages SET folder=$2,read_at=CASE WHEN $3 THEN coalesce(read_at,now()) ELSE read_at END WHERE id=$1 RETURNING `+strings.ReplaceAll(messageColumns, "msg.", ""), m.ID, folder, r.MarkRead))
		if err != nil {
			return err
		}
		if r.Stop {
			break
		}
	}
	if !a.Vacation.Active(time.Now()) || m.Folder == "Junk" || m.Folder == "Trash" {
		return nil
	}
	var address string
	if err = tx.QueryRow(ctx, `SELECT m.local_part||'@'||d.domain FROM mailboxes m JOIN domains d ON d.id=m.domain_id WHERE m.id=$1`, p.MailboxID).Scan(&address); err != nil {
		return err
	}
	recipient := vacationRecipient(p.Raw, p.EnvelopeFrom, address)
	if recipient == "" {
		return nil
	}
	var count int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM vacation_jobs WHERE mailbox_id=$1 AND created_at>now()-interval '24 hours'`, p.MailboxID).Scan(&count); err != nil {
		return err
	}
	if count >= 100 {
		return nil
	}
	tag, err := tx.Exec(ctx, `INSERT INTO vacation_recipients(mailbox_id,recipient) VALUES($1,$2) ON CONFLICT(mailbox_id,recipient) DO UPDATE SET reserved_at=now() WHERE vacation_recipients.reserved_at<=now()-interval '7 days'`, p.MailboxID, recipient)
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO vacation_jobs(mailbox_id,message_id,config_version,recipient,subject,body) VALUES($1,$2,$3,$4,$5,$6)`, p.MailboxID, m.ID, a.Version, recipient, a.Vacation.Subject, a.Vacation.Text)
	return err
}

func vacationRecipient(raw []byte, envelope, address string) string {
	recipient := strings.ToLower(strings.TrimSpace(envelope))
	addr, err := mail.ParseAddress(recipient)
	if err != nil || addr.Address != recipient || strings.EqualFold(recipient, address) {
		return ""
	}
	local := strings.SplitN(recipient, "@", 2)[0]
	for _, reserved := range []string{"mailer-daemon", "postmaster", "noreply", "no-reply", "-request", "bounce"} {
		if strings.Contains(local, reserved) {
			return ""
		}
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return ""
	}
	h := msg.Header
	for _, v := range h["Auto-Submitted"] {
		if !strings.EqualFold(strings.TrimSpace(v), "no") {
			return ""
		}
	}
	for key, values := range h {
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "list-") || lower == "x-auto-response-suppress" || lower == "x-autoreply" || lower == "x-autorespond" {
			return ""
		}
		if lower == "precedence" {
			for _, v := range values {
				switch strings.ToLower(strings.TrimSpace(v)) {
				case "bulk", "list", "junk":
					return ""
				}
			}
		}
	}
	typ, _, _ := mime.ParseMediaType(h.Get("Content-Type"))
	if typ == "multipart/report" || typ == "message/delivery-status" || typ == "message/disposition-notification" {
		return ""
	}
	// Do not disclose vacation state for Bcc, aliases or forwarded list deliveries.
	for _, key := range []string{"To", "Cc"} {
		for _, v := range h[key] {
			list, err := mail.ParseAddressList(v)
			if err != nil {
				continue
			}
			for _, to := range list {
				if strings.EqualFold(to.Address, address) {
					return recipient
				}
			}
		}
	}
	return ""
}
