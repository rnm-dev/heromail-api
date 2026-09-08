package email

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/hibiken/asynq"

	"github.com/rnm/heromail/backend/internal/maildomain"
	"github.com/rnm/heromail/backend/internal/provider"
	"github.com/rnm/heromail/backend/internal/storage"
)

// TypeSend is the asynq task type for delivering one stored message.
const TypeSend = "email:send"

// maxAttempts is how many times the worker tries before giving up. The backoff
// asynq applies between attempts is exponential, so this spans roughly a day —
// long enough to ride out a receiver's temporary failure, short enough that a
// genuinely undeliverable message does not sit forever.
const maxAttempts = 8

// SendPayload carries only the id: the message itself lives in Postgres, so a
// task cannot go stale or disagree with the row it refers to.
type SendPayload struct {
	EmailID string `json:"email_id"`
}

// Enqueuer hands work to the queue. It is an interface so the service can be
// tested without Redis.
type Enqueuer interface {
	EnqueueSend(ctx context.Context, emailID string) error
}

// AsynqEnqueuer is the real implementation.
type AsynqEnqueuer struct {
	client *asynq.Client
}

func NewEnqueuer(redisAddr string) *AsynqEnqueuer {
	return &AsynqEnqueuer{client: asynq.NewClient(asynq.RedisClientOpt{Addr: redisAddr})}
}

func (e *AsynqEnqueuer) Close() error { return e.client.Close() }

func (e *AsynqEnqueuer) EnqueueSend(ctx context.Context, emailID string) error {
	payload, err := json.Marshal(SendPayload{EmailID: emailID})
	if err != nil {
		return err
	}

	_, err = e.client.EnqueueContext(ctx, asynq.NewTask(TypeSend, payload),
		asynq.MaxRetry(maxAttempts),
		asynq.Timeout(2*time.Minute),
		// Deduplicate on the email id: a retried HTTP request that somehow
		// enqueues twice still results in one delivery.
		asynq.TaskID(emailID),
	)
	if errors.Is(err, asynq.ErrTaskIDConflict) {
		// Already queued or running. Nothing to do, and not an error.
		return nil
	}
	return err
}

// Worker performs the deliveries.
type Worker struct {
	store  *Store
	sender provider.Sender
	// blobs may be nil: a message with no attachments never touches it, which
	// is what lets the worker run before a bucket is configured.
	blobs storage.Store
	// domains may be nil, same seam: a message From an unclaimed or
	// unverified domain sends unsigned either way, so a deployment that has
	// not wired domain management up yet is not blocked from sending mail.
	domains *maildomain.Service
}

func NewWorker(store *Store, sender provider.Sender, blobs storage.Store, domains *maildomain.Service) *Worker {
	return &Worker{store: store, sender: sender, blobs: blobs, domains: domains}
}

// HandleSend delivers one message.
//
// Returning an error asks asynq to retry with backoff. On the final attempt the
// message is marked dead instead, because a retry that will never happen must
// not leave the row looking like it is still being worked on.
func (w *Worker) HandleSend(ctx context.Context, task *asynq.Task) error {
	var payload SendPayload
	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		// A payload we cannot read will never become readable.
		return fmt.Errorf("%w: unmarshal payload: %v", asynq.SkipRetry, err)
	}

	// Both are absent outside an asynq worker context; treating that as "no
	// retries left" would mark a message dead on its first failure, so fall
	// back to the configured budget.
	retried, _ := asynq.GetRetryCount(ctx)
	maxRetry, ok := asynq.GetMaxRetry(ctx)
	if !ok {
		maxRetry = maxAttempts
	}
	return w.Deliver(ctx, payload.EmailID, retried, maxRetry)
}

// Deliver is the delivery itself, with the retry budget passed in rather than
// read from the task context. That keeps HandleSend a thin adapter and lets a
// test reach the give-up branch without waiting for eight real retries.
func (w *Worker) Deliver(ctx context.Context, emailID string, retried, maxRetry int) error {
	email, err := w.store.ByIDUnscoped(ctx, emailID)
	switch {
	case errors.Is(err, ErrNotFound):
		// The workspace was deleted while the task sat in the queue.
		log.Printf("email %s: no longer exists, dropping task", emailID)
		return nil
	case err != nil:
		return fmt.Errorf("load email %s: %w", emailID, err)
	}

	if email.Status.Terminal() {
		// Already sent or given up on; a duplicate task must not re-send.
		return nil
	}

	claimed, err := w.store.MarkProcessing(ctx, email.ID)
	if errors.Is(err, ErrNotFound) {
		// Another worker claimed it first.
		return nil
	}
	if err != nil {
		return fmt.Errorf("claim email %s: %w", email.ID, err)
	}

	attachments, closeAttachments, err := w.loadAttachments(ctx, claimed.ID)
	if err != nil {
		// A missing bucket or a bucket that stopped answering is a transport
		// problem, not a bad message — go through the normal retry path
		// rather than a bespoke branch.
		return w.giveUpOrRetry(ctx, claimed, retried, maxRetry, fmt.Errorf("load attachments: %w", err))
	}
	defer closeAttachments()

	dkim, err := w.resolveDKIM(ctx, claimed)
	if err != nil {
		// Anything other than "not claimed" / "not verified" — a corrupt key,
		// SECRET_KEY changed out from under us, the database being briefly
		// unreachable — is our fault, not the sender's, and must not result
		// in mail going out unsigned for a domain that committed to signing
		// it. Retry rather than silently drop the signature.
		return w.giveUpOrRetry(ctx, claimed, retried, maxRetry, fmt.Errorf("resolve DKIM key: %w", err))
	}

	messageID, sendErr := w.sender.Send(ctx, provider.Message{
		From:        claimed.FromAddr,
		To:          claimed.ToAddrs,
		Cc:          claimed.CcAddrs,
		Bcc:         claimed.BccAddrs,
		Subject:     claimed.Subject,
		HTMLBody:    deref(claimed.HTMLBody),
		TextBody:    deref(claimed.TextBody),
		Attachments: attachments,
		DKIM:        dkim,
	})
	if sendErr == nil {
		if _, err := w.store.MarkSent(ctx, claimed.ID, messageID); err != nil {
			// The message is genuinely out. Failing here would make asynq
			// retry and send it twice, which is worse than a wrong row.
			log.Printf("email %s: sent as %s but recording it failed: %v", claimed.ID, messageID, err)
		}
		return nil
	}

	return w.giveUpOrRetry(ctx, claimed, retried, maxRetry, sendErr)
}

// giveUpOrRetry records a failed attempt as either dead (no budget left) or
// failed (asynq will retry with backoff), and returns nil or an error to
// match — nil tells asynq there is nothing more to do, an error asks it to
// try again.
func (w *Worker) giveUpOrRetry(ctx context.Context, claimed *Email, retried, maxRetry int, sendErr error) error {
	if retried >= maxRetry {
		if _, err := w.store.MarkDead(ctx, claimed.ID, sendErr.Error()); err != nil {
			log.Printf("email %s: marking dead failed: %v", claimed.ID, err)
		}
		log.Printf("email %s: giving up after %d attempts: %v", claimed.ID, retried+1, sendErr)
		// Returning nil: asynq has no retries left anyway, and the outcome is
		// already recorded on the row.
		return nil
	}

	if _, err := w.store.MarkFailed(ctx, claimed.ID, sendErr.Error()); err != nil {
		log.Printf("email %s: marking failed failed: %v", claimed.ID, err)
	}
	return fmt.Errorf("send email %s (attempt %d/%d): %w", claimed.ID, retried+1, maxRetry, sendErr)
}

// resolveDKIM looks up the signing key for the message's From domain, scoped
// to the workspace that sent it. A nil, nil return means "send unsigned" —
// which is the normal outcome for a From address on a domain the workspace
// never claimed or has not verified yet, exactly as permissive as sending
// From that address is today.
func (w *Worker) resolveDKIM(ctx context.Context, claimed *Email) (*provider.DKIM, error) {
	if w.domains == nil {
		return nil, nil
	}

	domain := domainOf(claimed.FromAddr)
	if domain == "" {
		return nil, nil
	}

	selector, privateDER, err := w.domains.SigningKeyForDomain(ctx, claimed.WorkspaceID, domain)
	switch {
	case errors.Is(err, maildomain.ErrNotFound), errors.Is(err, maildomain.ErrNotVerified), errors.Is(err, maildomain.ErrNoActiveKey):
		return nil, nil
	case err != nil:
		return nil, err
	}
	return &provider.DKIM{Domain: domain, Selector: selector, PrivateKeyDER: privateDER}, nil
}

// domainOf returns the part of an address after the @, or "" if there isn't
// one — which should be impossible for a row that passed validation, but a
// worker trusts nothing it did not just check.
func domainOf(addr string) string {
	at := strings.LastIndex(addr, "@")
	if at < 0 || at+1 >= len(addr) {
		return ""
	}
	return addr[at+1:]
}

// loadAttachments fetches every file attached to emailID and opens a reader
// on each. The returned closer must be called once the send attempt is done,
// successful or not, to release the S3 connections.
func (w *Worker) loadAttachments(ctx context.Context, emailID string) ([]provider.Attachment, func(), error) {
	rows, err := w.store.AttachmentsByEmailID(ctx, emailID)
	if err != nil {
		return nil, func() {}, fmt.Errorf("list attachments: %w", err)
	}
	if len(rows) == 0 {
		return nil, func() {}, nil
	}
	if w.blobs == nil {
		return nil, func() {}, storage.ErrNotConfigured
	}

	out := make([]provider.Attachment, 0, len(rows))
	var opened []io.Closer
	closeAll := func() {
		for _, c := range opened {
			c.Close()
		}
	}
	for _, a := range rows {
		rc, err := w.blobs.Get(ctx, a.StorageKey)
		if err != nil {
			closeAll()
			return nil, func() {}, fmt.Errorf("fetch %s: %w", a.Filename, err)
		}
		opened = append(opened, rc)
		out = append(out, provider.Attachment{
			Filename:    a.Filename,
			ContentType: a.ContentType,
			Content:     rc,
		})
	}
	return out, closeAll, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
