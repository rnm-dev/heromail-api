package inbound

import (
	"bytes"
	"context"
	"errors"
	"mime"
	"net/mail"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Smart inbox categories. They sort the web Inbox into tabs; folders, IMAP
// and the message itself are untouched.
const (
	CategoryPeople        = "people"
	CategoryNotifications = "notifications"
	CategoryNewsletters   = "newsletters"
)

func ValidCategory(c string) bool {
	return c == CategoryPeople || c == CategoryNotifications || c == CategoryNewsletters
}

var (
	// Mailbox-service headers used by bulk senders (Mailgun, SendGrid, Mailchimp,
	// SES, Unisender, Sendinblue, Mailjet, Salesforce, HubSpot, ...).
	espHeader           = regexp.MustCompile(`^(x-mailgun|x-sg-|x-sendgrid|x-mc-user|x-mailchimp|x-campaign|x-unisender|x-sendpulse|x-mailer-recptid|x-ses-|x-sfmc|x-marketo|x-hubspot|x-mandrill|x-mj-|x-sib-|x-csa-complaints|x-emarsys|x-rpcampaign|x-mailru-msgtype)`)
	robotSender         = regexp.MustCompile(`(no[-_.]?reply|do[-_.]?not[-_.]?reply|mailer-daemon|postmaster|notifications?@|notify@|alerts?@|bounces?[@+-])`)
	transactionalSender = regexp.MustCompile(`(notif|alert|no[-_.]?reply|security|account|billing|receipt|invoice|calendar)`)
	promoSubject        = regexp.MustCompile(`(?i)(скидк|акци|распродаж|вебинар|webinar|\bsale\b|% off|\bpromo|бесплатн|розыгрыш|успейте|подписк|\boffer)`)
	calendarReply       = regexp.MustCompile(`(?i)^(accepted|declined|tentative|tentatively accepted|принято|отклонено|под вопросом)\s*:`)
	calendarInvite      = regexp.MustCompile(`(?i)^(invitation|updated invitation|приглашение|обновленное приглашение)\s*:`)
	threadSubject       = regexp.MustCompile(`(?i)^(re|aw|ответ|fw|fwd)\s*:`)
)

// classifyHeaders sorts a message by its headers alone. Sender history, which
// outranks every header signal, is checked by the caller.
func classifyHeaders(raw []byte, from, subject string) (category, reason string) {
	from = strings.ToLower(from)
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return CategoryPeople, "unparsed"
	}
	h := msg.Header
	typ, params, _ := mime.ParseMediaType(h.Get("Content-Type"))
	body := bytes.ToLower(raw)
	switch {
	case typ == "multipart/report" || strings.HasPrefix(from, "mailer-daemon@") || strings.HasPrefix(from, "postmaster@"):
		return CategoryNotifications, "delivery-report"
	case h.Get("Auto-Submitted") != "" && !strings.EqualFold(strings.TrimSpace(h.Get("Auto-Submitted")), "no"):
		return CategoryNotifications, "auto-submitted"
	case strings.EqualFold(params["method"], "reply") || bytes.Contains(body, []byte("method:reply")) || calendarReply.MatchString(subject):
		return CategoryNotifications, "calendar-reply"
	}
	var bulk []string
	if h.Get("List-Unsubscribe") != "" {
		bulk = append(bulk, "list-unsubscribe")
	}
	if h.Get("List-Id") != "" {
		bulk = append(bulk, "list-id")
	}
	switch strings.ToLower(strings.TrimSpace(h.Get("Precedence"))) {
	case "bulk", "list", "junk":
		bulk = append(bulk, "precedence")
	}
	if h.Get("Feedback-Id") != "" {
		bulk = append(bulk, "feedback-id")
	}
	for key := range h {
		if espHeader.MatchString(strings.ToLower(key)) {
			bulk = append(bulk, "esp")
			break
		}
	}
	domain := from[strings.LastIndex(from, "@")+1:]
	robot := robotSender.MatchString(from)
	if len(bulk) > 0 {
		reason = strings.Join(bulk, ",")
		// Service alerts are often sent through the same platforms as marketing;
		// an unsubscribe link is what makes something a subscription.
		if h.Get("List-Unsubscribe") == "" && transactionalSender.MatchString(from) && !promoSubject.MatchString(subject) {
			return CategoryNotifications, reason
		}
		return CategoryNewsletters, reason
	}
	switch {
	case robot:
		return CategoryNotifications, "robot-sender"
	case strings.HasSuffix(domain, ".gov.kz"):
		return CategoryNotifications, "government"
	case bytes.Contains(body, []byte("text/calendar")) || calendarInvite.MatchString(subject):
		return CategoryPeople, "calendar-invite"
	case h.Get("In-Reply-To") != "" || threadSubject.MatchString(subject):
		return CategoryPeople, "thread"
	}
	return CategoryPeople, "no-signal"
}

type queryRower interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

// classify decides a message's category. Order: the user's correction for
// this sender, then correspondence history, then headers.
func classify(ctx context.Context, q queryRower, mailboxID string, raw []byte, from, subject string) (string, string, error) {
	from = strings.ToLower(strings.TrimSpace(from))
	if from != "" {
		var category string
		err := q.QueryRow(ctx, `SELECT category FROM sender_categories WHERE mailbox_id=$1 AND sender=$2`, mailboxID, from).Scan(&category)
		if err == nil {
			return category, "user-choice", nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return "", "", err
		}
		var history string
		err = q.QueryRow(ctx, `
SELECT CASE
 WHEN EXISTS (SELECT 1 FROM emails e WHERE e.from_addr=(m.local_part||'@'||d.domain)::citext
   AND $2=ANY(SELECT lower(a) FROM unnest(e.to_addrs||e.cc_addrs) a)) THEN 'sent-to'
 WHEN EXISTS (SELECT 1 FROM contacts c WHERE c.user_id=m.owner_user_id AND lower(c.email)=$2) THEN 'contact'
 WHEN split_part($2,'@',2)=d.domain THEN 'same-domain'
 ELSE '' END
FROM mailboxes m JOIN domains d ON d.id=m.domain_id WHERE m.id=$1`, mailboxID, from).Scan(&history)
		if err != nil {
			return "", "", err
		}
		if history != "" && (history != "same-domain" || !robotSender.MatchString(from)) {
			return CategoryPeople, history, nil
		}
	}
	category, reason := classifyHeaders(raw, from, subject)
	return category, reason, nil
}

// SetSenderCategory records a user's correction and applies it to every
// message from that sender in the mailbox, so the Inbox tabs agree at once.
func (s *Store) SetSenderCategory(ctx context.Context, mailboxID, messageID, category string, remember bool) (int64, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	var from string
	if err = tx.QueryRow(ctx, `UPDATE messages SET category=$3, category_reason='user-choice' WHERE mailbox_id=$1 AND id=$2 RETURNING lower(coalesce(from_addr,''))`, mailboxID, messageID, category).Scan(&from); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrNoMailbox
		}
		return 0, err
	}
	updated := int64(1)
	if remember && from != "" {
		if _, err = tx.Exec(ctx, `INSERT INTO sender_categories(mailbox_id,sender,category) VALUES($1,$2,$3) ON CONFLICT(mailbox_id,sender) DO UPDATE SET category=$3,updated_at=now()`, mailboxID, from, category); err != nil {
			return 0, err
		}
		tag, err := tx.Exec(ctx, `UPDATE messages SET category=$3, category_reason='user-choice' WHERE mailbox_id=$1 AND lower(from_addr)=$2 AND id<>$4`, mailboxID, from, category, messageID)
		if err != nil {
			return 0, err
		}
		updated += tag.RowsAffected()
	}
	return updated, tx.Commit(ctx)
}

// Reclassify sorts stored messages that were never classified (or every
// message when all is set). User corrections are kept. dryRun reports counts
// without writing.
func (s *Store) Reclassify(ctx context.Context, mailboxID string, all, dryRun bool) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, mailbox_id, coalesce(from_addr,''), subject, substring(raw from 1 for 262144)
 FROM messages WHERE ($1='' OR mailbox_id=$1::uuid) AND category_reason<>'user-choice' AND ($2 OR category_reason='')`, mailboxID, all)
	if err != nil {
		return nil, err
	}
	type item struct {
		id, box, from, subject string
		raw                    []byte
	}
	var items []item
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.id, &it.box, &it.from, &it.subject, &it.raw); err != nil {
			rows.Close()
			return nil, err
		}
		items = append(items, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, it := range items {
		category, reason, err := classify(ctx, s.pool, it.box, it.raw, it.from, it.subject)
		if err != nil {
			return nil, err
		}
		counts[category]++
		if dryRun {
			continue
		}
		if _, err := s.pool.Exec(ctx, `UPDATE messages SET category=$2, category_reason=$3 WHERE id=$1 AND category_reason<>'user-choice'`, it.id, category, reason); err != nil {
			return nil, err
		}
	}
	return counts, nil
}
