// Package email owns outbound messages: the store that persists them, the
// service that sends them, and the HTTP handlers on top.
package email

import (
	"encoding/json"
	"time"
)

// Status mirrors the email_status enum in Postgres.
type Status string

const (
	StatusQueued     Status = "queued"
	StatusProcessing Status = "processing"
	StatusSent       Status = "sent"
	StatusFailed     Status = "failed"
	// StatusDead is terminal: retries are exhausted and the worker gives up.
	StatusDead Status = "dead"
)

// Terminal reports whether the status will never change again on its own.
func (s Status) Terminal() bool { return s == StatusSent || s == StatusDead }

// EventType mirrors the email_event_type enum. It is deliberately wider than
// Status: delivery, bounces and complaints happen to a message after it was
// handed off, they are not states the sender moves it through.
type EventType string

const (
	EventQueued     EventType = "queued"
	EventProcessing EventType = "processing"
	EventSent       EventType = "sent"
	EventFailed     EventType = "failed"
	EventBounced    EventType = "bounced"
	EventComplained EventType = "complained"
	EventDelivered  EventType = "delivered"
)

// Email is one outbound message, and the unit of idempotency.
type Email struct {
	ID          string   `json:"id"`
	WorkspaceID string   `json:"workspace_id"`
	FromAddr    string   `json:"from"`
	ToAddrs     []string `json:"to"`
	CcAddrs     []string `json:"cc"`
	BccAddrs    []string `json:"bcc"`
	Subject     string   `json:"subject"`
	HTMLBody    *string  `json:"html,omitempty"`
	TextBody    *string  `json:"text,omitempty"`

	Status            Status  `json:"status"`
	ProviderMessageID *string `json:"provider_message_id"`
	IdempotencyKey    *string `json:"idempotency_key,omitempty"`
	Attempts          int     `json:"attempts"`
	LastError         *string `json:"last_error"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Attachment is a file stored in object storage, either waiting to be
// referenced by a send request or already attached to one.
type Attachment struct {
	ID          string    `json:"id"`
	WorkspaceID string    `json:"workspace_id"`
	EmailID     *string   `json:"email_id,omitempty"`
	Filename    string    `json:"filename"`
	ContentType string    `json:"content_type"`
	SizeBytes   int64     `json:"size_bytes"`
	ChecksumSHA []byte    `json:"-"`
	StorageKey  string    `json:"-"`
	CreatedAt   time.Time `json:"created_at"`
}

// Event is an append-only record of something that happened to an email.
type Event struct {
	ID        string          `json:"id"`
	EmailID   string          `json:"email_id"`
	Type      EventType       `json:"type"`
	Detail    json.RawMessage `json:"detail,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}
