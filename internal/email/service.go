package email

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/rnm/heromail/backend/internal/storage"
)

// ErrValidation wraps anything the caller got wrong about the request.
var ErrValidation = errors.New("validation failed")

// ErrEnqueueFailed means the message was recorded but could not be handed to
// the queue, so nothing will deliver it. The email is returned alongside the
// error so the caller can still report its id.
var ErrEnqueueFailed = errors.New("could not queue the message")

// ErrStorageNotConfigured means this deployment has no S3 bucket set yet.
// Attachments are wired end to end before real credentials exist.
var ErrStorageNotConfigured = errors.New("attachment storage is not configured")

// ErrAttachmentTooLarge means a single upload exceeded ATTACHMENT_MAX_BYTES.
var ErrAttachmentTooLarge = errors.New("attachment is too large")

// ErrAttachmentsTooLarge means the sum of a message's attachments exceeded
// ATTACHMENT_MAX_TOTAL_BYTES.
var ErrAttachmentsTooLarge = errors.New("attachments are too large combined")

// ErrFromNotAllowed means the workspace has not proven it owns the domain in
// the From address.
var ErrFromNotAllowed = errors.New("sender domain is not a verified domain of this workspace")

// defaultAttachmentMaxBytes and defaultAttachmentMaxTotalBytes are the
// fallback limits: 25MB is the ceiling most receiving MTAs (Gmail, Outlook)
// apply to an entire message, so there is no point accepting more than that
// per file or in total.
const (
	defaultAttachmentMaxBytes      = 25 << 20
	defaultAttachmentMaxTotalBytes = 25 << 20
)

func attachmentMaxBytes() int64 { return envBytes("ATTACHMENT_MAX_BYTES", defaultAttachmentMaxBytes) }
func attachmentMaxTotalBytes() int64 {
	return envBytes("ATTACHMENT_MAX_TOTAL_BYTES", defaultAttachmentMaxTotalBytes)
}

// envBytes reads at call time, not at startup, so tests can lower a limit with
// t.Setenv instead of sending a 25MB file.
func envBytes(name string, fallback int64) int64 {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

// SendRequest is the JSON body of POST /v1/emails.
//
// At least one body is required, expressed as a pair of required_without tags:
// each body is required only when the other is absent, so exactly one is
// enough and neither is not. This mirrors the CHECK constraint on the table.
type SendRequest struct {
	From    string   `json:"from"    validate:"required,email"`
	To      []string `json:"to"      validate:"required,min=1,max=50,dive,required,email"`
	Cc      []string `json:"cc" validate:"max=50,dive,required,email"`
	Bcc     []string `json:"bcc" validate:"max=50,dive,required,email"`
	Subject string   `json:"subject" validate:"max=998"`
	HTML    string   `json:"html"    validate:"required_without=Text"`
	Text    string   `json:"text"    validate:"required_without=HTML"`
	// AttachmentIDs are ids returned by UploadAttachment, still unattached.
	AttachmentIDs []string `json:"-" validate:"max=20,dive,uuid"`
}

// DomainGuard answers whether a workspace may send as a domain. It is an
// interface so this package keeps no dependency on maildomain, and so a test
// can allow or refuse without a database.
type DomainGuard interface {
	AllowsSender(ctx context.Context, workspaceID, domain string) error
}

// Service turns a validated request into a stored, queued email.
type Service struct {
	store    *Store
	queue    Enqueuer
	blobs    storage.Store
	domains  DomainGuard
	validate *validator.Validate
}

// WithDomainGuard turns on sender-domain enforcement.
//
// Optional, and off in tests that are about something else, because switching
// it on changes what every send means: without it a workspace may claim any
// From address, which is how this started and is not something to leave on in
// production.
func (s *Service) WithDomainGuard(guard DomainGuard) *Service {
	s.domains = guard
	return s
}

// checkFrom refuses a From address on a domain the workspace has not verified.
//
// Asks about ownership, not about signing. Those looked like the same question
// and are not: a domain can be verified and still have no active DKIM key, and
// refusing mail from a domain the workspace demonstrably owns because we cannot
// sign it would be the wrong failure.
func (s *Service) checkFrom(ctx context.Context, workspaceID, from string) error {
	if s.domains == nil {
		return nil
	}
	at := strings.LastIndex(from, "@")
	if at < 0 || at+1 >= len(from) {
		return fmt.Errorf("%w: %s", ErrValidation, "From is not an address")
	}
	domain := strings.ToLower(from[at+1:])

	if err := s.domains.AllowsSender(ctx, workspaceID, domain); err != nil {
		return fmt.Errorf("%w: %s", ErrFromNotAllowed, domain)
	}
	return nil
}

// NewService wires a Service. blobs may be nil — a deployment with no bucket
// configured yet still sends mail without attachments; only UploadAttachment
// and messages that reference attachments need it.
func NewService(store *Store, queue Enqueuer, blobs storage.Store) *Service {
	return &Service{
		store:    store,
		queue:    queue,
		blobs:    blobs,
		validate: validator.New(validator.WithRequiredStructEnabled()),
	}
}

// Send records the message and hands it to the provider.
//
// The row is written before the send attempt, not after: if the process dies
// mid-send we would rather have a queued email with no delivery than a
// delivered email with no record of it.
func (s *Service) Send(ctx context.Context, workspaceID, idempotencyKey string, req SendRequest) (*Email, error) {
	if err := s.validate.Struct(req); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrValidation, describeValidation(err))
	}

	if len(req.To)+len(req.Cc)+len(req.Bcc) > 50 {
		return nil, fmt.Errorf("%w: at most 50 recipients in total", ErrValidation)
	}
	if strings.TrimSpace(req.Text) == "" && strings.TrimSpace(req.HTML) == "" {
		return nil, fmt.Errorf("%w: message body is required", ErrValidation)
	}
	if err := s.checkFrom(ctx, workspaceID, req.From); err != nil {
		return nil, err
	}

	// An earlier request under the same key already did this work.
	if idempotencyKey != "" {
		existing, err := s.store.ByIdempotencyKey(ctx, workspaceID, idempotencyKey)
		switch {
		case err == nil:
			if existing.FromAddr != req.From || !slices.Equal(existing.ToAddrs, req.To) || !slices.Equal(existing.CcAddrs, req.Cc) || !slices.Equal(existing.BccAddrs, req.Bcc) || existing.Subject != req.Subject || deref(existing.TextBody) != req.Text || deref(existing.HTMLBody) != req.HTML {
				return nil, fmt.Errorf("%w: idempotency key belongs to a different message", ErrValidation)
			}
			attached, err := s.store.AttachmentsByEmailID(ctx, existing.ID)
			if err != nil {
				return nil, err
			}
			ids := make([]string, 0, len(attached))
			for _, a := range attached {
				ids = append(ids, a.ID)
			}
			expected := slices.Clone(req.AttachmentIDs)
			slices.Sort(ids)
			slices.Sort(expected)
			if !slices.Equal(ids, expected) {
				return nil, fmt.Errorf("%w: attachment list differs from original request", ErrValidation)
			}
			// A queue outage can leave a recorded message without a task.
			// EnqueueSend deduplicates tasks by email ID; the worker also
			// refuses terminal messages. Recover using the same message ID.
			if existing.Status == StatusQueued {
				if err := s.queue.EnqueueSend(ctx, existing.ID); err != nil {
					return existing, fmt.Errorf("%w: %v", ErrEnqueueFailed, err)
				}
			}
			return existing, nil
		case !errors.Is(err, ErrNotFound):
			return nil, fmt.Errorf("look up idempotency key: %w", err)
		}
	}

	// Resolve attachments before writing the email row: a request referencing
	// a bad id must fail cleanly, not leave a queued email with half its
	// attachments missing.
	var attachments []Attachment
	if len(req.AttachmentIDs) > 0 {
		var err error
		attachments, err = s.store.AttachmentsByIDs(ctx, workspaceID, req.AttachmentIDs)
		if err != nil {
			return nil, fmt.Errorf("look up attachments: %w", err)
		}
		if len(attachments) != len(req.AttachmentIDs) {
			return nil, fmt.Errorf("%w: attachment", ErrNotFound)
		}
		var total int64
		for _, a := range attachments {
			total += a.SizeBytes
		}
		if total > attachmentMaxTotalBytes() {
			return nil, ErrAttachmentsTooLarge
		}
	}

	email, err := s.store.Create(ctx, CreateParams{
		WorkspaceID:    workspaceID,
		FromAddr:       req.From,
		ToAddrs:        req.To,
		CcAddrs:        req.Cc,
		BccAddrs:       req.Bcc,
		Subject:        req.Subject,
		HTMLBody:       req.HTML,
		TextBody:       req.Text,
		IdempotencyKey: idempotencyKey,
	})
	if errors.Is(err, ErrDuplicateIdempotencyKey) {
		// Two requests raced with the same key and the unique index picked a
		// winner. Return the row the winner created rather than failing.
		return s.store.ByIdempotencyKey(ctx, workspaceID, idempotencyKey)
	}
	if err != nil {
		return nil, err
	}

	if len(req.AttachmentIDs) > 0 {
		claimed, err := s.store.AttachToEmail(ctx, workspaceID, email.ID, req.AttachmentIDs)
		if err != nil {
			return email, fmt.Errorf("attach files: %w", err)
		}
		if int(claimed) != len(req.AttachmentIDs) {
			// Someone else claimed one between the lookup above and here — the
			// same race the unique index resolves for idempotency keys, just
			// without a "correct" winner to fall back to. The email row stays;
			// its GET reflects whichever attachments actually landed.
			return email, fmt.Errorf("%w: attachment was claimed by another request", ErrAttachmentNotFound)
		}
	}

	if err := s.queue.EnqueueSend(ctx, email.ID); err != nil {
		// The row exists and is queued, but nothing will pick it up. Failing
		// the request is right: the caller must know the message is stuck, and
		// a retry will find the same row through its idempotency key.
		log.Printf("email %s: enqueue failed: %v", email.ID, err)
		return email, fmt.Errorf("%w: %v", ErrEnqueueFailed, err)
	}
	return email, nil
}

// ByID loads one email within the workspace.
func (s *Service) ByID(ctx context.Context, workspaceID, id string) (*Email, error) {
	return s.store.ByID(ctx, workspaceID, id)
}

// AttachmentsForEmail lists what is attached to one message.
func (s *Service) AttachmentsForEmail(ctx context.Context, emailID string) ([]Attachment, error) {
	return s.store.AttachmentsByEmailID(ctx, emailID)
}

// UploadAttachment reads r into object storage and records it, unattached.
//
// A multipart part carries no reliable Content-Length, so the size is never
// trusted up front: r is read into memory up to the cap plus one byte, which
// both bounds the read and detects an oversized file without needing the
// bucket to support unknown-length uploads. The cap is small enough (25MB by
// default) that buffering it is cheap.
func (s *Service) UploadAttachment(ctx context.Context, workspaceID, filename, contentType string, r io.Reader) (*Attachment, error) {
	if s.blobs == nil {
		return nil, ErrStorageNotConfigured
	}
	filename = strings.TrimSpace(filename)
	if filename == "" {
		return nil, fmt.Errorf("%w: filename is required", ErrValidation)
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	limit := attachmentMaxBytes()
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read attachment: %w", err)
	}
	if int64(len(data)) > limit {
		return nil, ErrAttachmentTooLarge
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("%w: file is empty", ErrValidation)
	}

	sum := sha256.Sum256(data)
	storageKey := workspaceID + "/" + uuid.NewString()
	if err := s.blobs.Put(ctx, storageKey, bytes.NewReader(data), int64(len(data)), contentType); err != nil {
		return nil, fmt.Errorf("store attachment: %w", err)
	}

	attachment, err := s.store.InsertAttachment(ctx, InsertAttachmentParams{
		WorkspaceID: workspaceID,
		Filename:    filename,
		ContentType: contentType,
		SizeBytes:   int64(len(data)),
		ChecksumSHA: sum[:],
		StorageKey:  storageKey,
	})
	if err != nil {
		_ = s.blobs.Delete(ctx, storageKey)
		return nil, fmt.Errorf("record attachment: %w", err)
	}
	return attachment, nil
}

func (s *Service) SearchForUser(ctx context.Context, userID, query string, limit int) ([]Email, error) {
	return s.store.SearchForUser(ctx, userID, query, limit)
}

// describeValidation turns validator's error set into one readable sentence.
func describeValidation(err error) string {
	var invalid *validator.InvalidValidationError
	if errors.As(err, &invalid) {
		return err.Error()
	}

	var fieldErrs validator.ValidationErrors
	if !errors.As(err, &fieldErrs) {
		return err.Error()
	}

	msg := ""
	for i, fe := range fieldErrs {
		if i > 0 {
			msg += "; "
		}
		switch fe.Tag() {
		case "required":
			msg += fmt.Sprintf("%s is required", fe.Field())
		case "required_without":
			msg += fmt.Sprintf("%s is required when %s is empty", fe.Field(), fe.Param())
		case "email":
			msg += fmt.Sprintf("%s must be a valid email address", fe.Field())
		case "min", "max":
			msg += fmt.Sprintf("%s violates %s=%s", fe.Field(), fe.Tag(), fe.Param())
		default:
			msg += fmt.Sprintf("%s failed %s", fe.Field(), fe.Tag())
		}
	}
	return msg
}
