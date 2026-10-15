package inbound

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rnm/heromail/backend/internal/email"
	"github.com/rnm/heromail/backend/internal/ratelimit"
)

// A transaction row lock serializes dispatch. A process crash releases it; the
// stable idempotency key recovers an email already recorded before that crash.
type VacationDispatcher struct {
	pool    *pgxpool.Pool
	emails  *email.Service
	limiter *ratelimit.Limiter
}

func NewVacationDispatcher(pool *pgxpool.Pool, emails *email.Service) *VacationDispatcher {
	return &VacationDispatcher{pool: pool, emails: emails}
}
func (d *VacationDispatcher) WithLimiter(l *ratelimit.Limiter) *VacationDispatcher {
	d.limiter = l
	return d
}
func (d *VacationDispatcher) Run(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		for i := 0; i < 10; i++ {
			found, err := d.ProcessNext(ctx, "")
			if err != nil {
				log.Printf("vacation dispatcher: %v", err)
				break
			}
			if !found {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (d *VacationDispatcher) ProcessNext(ctx context.Context, box string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var id, mailbox, recipient, subject, body string
	var version, attempts int
	var created time.Time
	err = tx.QueryRow(ctx, `SELECT id,mailbox_id,recipient,subject,body,config_version,attempts,created_at FROM vacation_jobs WHERE status='pending' AND due_at<=now() AND ($1='' OR mailbox_id=nullif($1,'')::uuid) ORDER BY due_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`, box).Scan(&id, &mailbox, &recipient, &subject, &body, &version, &attempts, &created)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	finish := func(status string, emailID *string, lastError *string, delay int, attempt bool) (bool, error) {
		_, e := tx.Exec(ctx, `UPDATE vacation_jobs SET status=$2,email_id=$3,last_error=$4,due_at=now()+$5*interval '1 second',attempts=attempts+CASE WHEN $6 THEN 1 ELSE 0 END WHERE id=$1`, id, status, emailID, lastError, delay, attempt)
		if e != nil {
			return true, e
		}
		return true, tx.Commit(ctx)
	}
	config, err := readAutomation(ctx, tx, mailbox, true)
	if err != nil {
		return true, err
	}
	mb, err := NewStore(d.pool).MailboxByID(ctx, mailbox)
	if err != nil {
		return true, err
	}
	existing, err := email.NewStore(d.pool).ByIdempotencyKey(ctx, mb.WorkspaceID, "vacation-job-"+id)
	if err != nil && !errors.Is(err, email.ErrNotFound) {
		return true, err
	}
	if existing == nil && (!config.Vacation.Active(time.Now()) || config.Version != version || time.Since(created) > 24*time.Hour) {
		return finish("skipped", nil, nil, 0, false)
	}
	// Quotas fail closed; retries of a previously recorded email don't spend again.
	if d.limiter != nil && existing == nil {
		limit := func(name string, fallback int) int {
			n, e := strconv.Atoi(os.Getenv(name))
			if e != nil || n <= 0 {
				return fallback
			}
			return n
		}
		for _, rule := range []ratelimit.Rule{{Name: "send:minute", Limit: limit("SEND_LIMIT_PER_MINUTE", 60), Window: time.Minute}, {Name: "send:day", Limit: limit("SEND_LIMIT_PER_DAY", 5000), Window: 24 * time.Hour}} {
			res := d.limiter.AllowStrict(ctx, rule, mb.WorkspaceID)
			if !res.Allowed {
				reason := "workspace send quota unavailable or exceeded"
				return finish("pending", nil, &reason, max(30, int(res.RetryAfter.Seconds())+1), false)
			}
		}
	}
	msg, sendErr := d.emails.Send(ctx, mb.WorkspaceID, "vacation-job-"+id, email.SendRequest{From: mb.Address, To: []string{recipient}, Subject: subject, Text: body, AutoReply: true})
	if sendErr != nil {
		status := "pending"
		if attempts+1 >= 8 {
			status = "dead"
		}
		reason := sendErr.Error()
		var emailID *string
		if msg != nil {
			emailID = &msg.ID
		}
		found, writeErr := finish(status, emailID, &reason, 60*(1<<min(attempts, 6)), true)
		if writeErr != nil {
			return found, writeErr
		}
		return true, fmt.Errorf("job %s: %w", id, sendErr)
	}
	return finish("queued", &msg.ID, nil, 0, true)
}
