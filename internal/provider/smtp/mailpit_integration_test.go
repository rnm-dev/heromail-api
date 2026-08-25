package smtp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rnm/heromail/backend/internal/provider"
)

// TestSendToMailpit exercises the real dev transport: it sends through the
// Mailpit container named by SMTP_HOST/SMTP_PORT and then reads the message
// back out of Mailpit's API. It is skipped unless MAILPIT_API_URL is set, so
// `go test ./...` stays hermetic outside compose.
func TestSendToMailpit(t *testing.T) {
	apiURL := os.Getenv("MAILPIT_API_URL")
	if apiURL == "" {
		t.Skip("MAILPIT_API_URL is not set; skipping Mailpit integration test")
	}

	s, err := NewFromEnv()
	if err != nil {
		t.Fatalf("NewFromEnv: %v", err)
	}

	subject := "Heromail provider check " + time.Now().UTC().Format(time.RFC3339)
	msg := provider.Message{
		From:     "noreply@acme.com",
		To:       []string{"viktor@acme.com"},
		Subject:  subject,
		TextBody: "plain body from the provider test",
		HTMLBody: "<p>html body from the provider test</p>",
		Headers:  map[string]string{"Reply-To": "support@acme.com"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	id, err := s.Send(ctx, msg)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	t.Logf("sent with Message-ID %s", id)

	found, err := findInMailpit(ctx, apiURL, id)
	if err != nil {
		t.Fatalf("query Mailpit: %v", err)
	}
	if found == nil {
		t.Fatalf("message %s did not arrive in Mailpit", id)
	}

	if found.Subject != subject {
		t.Errorf("Mailpit subject = %q, want %q", found.Subject, subject)
	}
	if len(found.To) != 1 || found.To[0].Address != "viktor@acme.com" {
		t.Errorf("Mailpit recipients = %+v", found.To)
	}
	t.Logf("Mailpit stored it as ID=%s Subject=%q", found.ID, found.Subject)
}

type mailpitMessage struct {
	ID        string `json:"ID"`
	MessageID string `json:"MessageID"`
	Subject   string `json:"Subject"`
	From      *struct {
		Address string `json:"Address"`
	} `json:"From"`
	To []struct {
		Address string `json:"Address"`
	} `json:"To"`
}

// findInMailpit polls the message list until the Message-ID shows up. Mailpit
// stores asynchronously, so a single immediate read can race the delivery.
func findInMailpit(ctx context.Context, apiURL, messageID string) (*mailpitMessage, error) {
	deadline := time.Now().Add(10 * time.Second)

	for {
		list, err := fetchMailpitMessages(ctx, apiURL)
		if err != nil {
			return nil, err
		}
		for i := range list {
			if strings.Trim(list[i].MessageID, "<>") == messageID {
				return &list[i], nil
			}
		}
		if time.Now().After(deadline) {
			return nil, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func fetchMailpitMessages(ctx context.Context, apiURL string) ([]mailpitMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(apiURL, "/")+"/api/v1/messages?limit=50", nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("mailpit returned %s: %s", resp.Status, body)
	}

	var payload struct {
		Messages []mailpitMessage `json:"messages"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	return payload.Messages, nil
}
