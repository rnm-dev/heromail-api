// Package fcm sends push notifications through the Firebase Cloud Messaging
// HTTP v1 API, authenticated as a service account with the OAuth JWT bearer
// grant. Stdlib only, like internal/meet: no Firebase SDK. iOS devices are
// reached through FCM too — Firebase forwards to APNs with the key uploaded in
// the Firebase console, so there is no APNs client here.
package fcm

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Scope is the narrowest scope that can send messages.
const Scope = "https://www.googleapis.com/auth/firebase.messaging"

var (
	// ErrNotConfigured means FCM_CREDENTIALS is unset: push is off.
	ErrNotConfigured = errors.New("fcm is not configured")
	// ErrUnregistered means the token will never work again (app uninstalled,
	// token rotated, token from another Firebase project). The device is
	// disabled rather than retried.
	ErrUnregistered = errors.New("fcm: registration token is no longer valid")
)

// Message is the FCM v1 `message` object, limited to what Heromail sends.
type Message struct {
	Token        string            `json:"token"`
	Notification *Notification     `json:"notification,omitempty"`
	Data         map[string]string `json:"data,omitempty"`
	Android      *AndroidConfig    `json:"android,omitempty"`
	APNS         *APNSConfig       `json:"apns,omitempty"`
}

type Notification struct {
	Title string `json:"title,omitempty"`
	Body  string `json:"body,omitempty"`
}

type AndroidConfig struct {
	CollapseKey  string               `json:"collapse_key,omitempty"`
	Priority     string               `json:"priority,omitempty"`
	Notification *AndroidNotification `json:"notification,omitempty"`
}

type AndroidNotification struct {
	ChannelID string `json:"channel_id,omitempty"`
	Tag       string `json:"tag,omitempty"`
}

type APNSConfig struct {
	Headers map[string]string `json:"headers,omitempty"`
	Payload map[string]any    `json:"payload,omitempty"`
}

type Client struct {
	projectID, email, tokenURI, apiURL string
	key                                *rsa.PrivateKey
	http                               *http.Client
	// attempts and backoff govern retries of transient failures (429, 5xx,
	// network); tests shrink backoff.
	attempts int
	backoff  time.Duration

	mu    sync.Mutex
	token string
	until time.Time
}

// FromEnv reads FCM_CREDENTIALS (path to the service account JSON key) and
// FCM_PROJECT_ID (defaults to the key's project_id).
func FromEnv() (*Client, error) {
	path := os.Getenv("FCM_CREDENTIALS")
	if path == "" {
		return nil, ErrNotConfigured
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read credentials: %w", err)
	}
	return New(raw, os.Getenv("FCM_PROJECT_ID"))
}

// New parses a service account JSON key. projectID may be empty to use the
// key's own project.
func New(credentials []byte, projectID string) (*Client, error) {
	var sa struct {
		Type        string `json:"type"`
		ProjectID   string `json:"project_id"`
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
		TokenURI    string `json:"token_uri"`
	}
	if err := json.Unmarshal(credentials, &sa); err != nil {
		return nil, fmt.Errorf("credentials: %w", err)
	}
	if sa.Type != "service_account" || sa.ClientEmail == "" || sa.PrivateKey == "" {
		return nil, errors.New("credentials: not a service account key")
	}
	block, _ := pem.Decode([]byte(sa.PrivateKey))
	if block == nil {
		return nil, errors.New("credentials: bad private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("credentials: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("credentials: not an RSA key")
	}
	if projectID = strings.TrimSpace(projectID); projectID == "" {
		projectID = sa.ProjectID
	}
	if projectID == "" {
		return nil, errors.New("FCM_PROJECT_ID is not set and the key names no project")
	}
	if sa.TokenURI == "" {
		sa.TokenURI = "https://oauth2.googleapis.com/token"
	}
	return &Client{projectID: projectID, email: sa.ClientEmail, tokenURI: sa.TokenURI, key: key,
		apiURL: "https://fcm.googleapis.com", http: &http.Client{Timeout: 15 * time.Second},
		attempts: 3, backoff: 500 * time.Millisecond}, nil
}

// ProjectID is what the client sends to, for the startup log.
func (c *Client) ProjectID() string { return c.projectID }

// Send delivers one message. Transient failures are retried with exponential
// backoff (honouring Retry-After); ErrUnregistered is returned at once.
func (c *Client) Send(ctx context.Context, msg Message) error {
	body, err := json.Marshal(map[string]any{"message": msg})
	if err != nil {
		return err
	}
	var last error
	wait := c.backoff
	for attempt := 1; attempt <= c.attempts; attempt++ {
		retryAfter, err := c.send(ctx, body)
		if err == nil || errors.Is(err, ErrUnregistered) || !isTransient(err) {
			return err
		}
		last = err
		if attempt == c.attempts {
			break
		}
		d := wait
		if retryAfter > d && retryAfter < 30*time.Second {
			d = retryAfter
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(d):
		}
		wait *= 2
	}
	return last
}

type transientError struct{ error }

func isTransient(err error) bool {
	var t transientError
	return errors.As(err, &t)
}

func (c *Client) send(ctx context.Context, body []byte) (time.Duration, error) {
	tok, err := c.accessToken(ctx)
	if err != nil {
		return 0, err
	}
	endpoint := c.apiURL + "/v1/projects/" + url.PathEscape(c.projectID) + "/messages:send"
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, transientError{fmt.Errorf("fcm: %w", err)}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode == http.StatusOK {
		return 0, nil
	}
	retryAfter := time.Duration(0)
	if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil {
		retryAfter = time.Duration(s) * time.Second
	}
	code, message := fcmError(raw)
	switch {
	case code == "UNREGISTERED", code == "SENDER_ID_MISMATCH",
		// INVALID_ARGUMENT also covers a malformed payload; only a bad token
		// disables the device.
		code == "INVALID_ARGUMENT" && strings.Contains(strings.ToLower(message), "registration token"):
		return 0, fmt.Errorf("%w (%s)", ErrUnregistered, code)
	case resp.StatusCode == http.StatusUnauthorized:
		// The cached access token was revoked or expired early: drop it so
		// the retry signs a fresh one.
		c.mu.Lock()
		c.token = ""
		c.mu.Unlock()
		return 0, transientError{fmt.Errorf("fcm: HTTP 401: %s", message)}
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return retryAfter, transientError{fmt.Errorf("fcm: HTTP %d %s: %s", resp.StatusCode, code, message)}
	default:
		return 0, fmt.Errorf("fcm: HTTP %d %s: %s", resp.StatusCode, code, message)
	}
}

// fcmError extracts the FcmError code (UNREGISTERED, QUOTA_EXCEEDED, ...) or,
// failing that, the Google API status.
func fcmError(raw []byte) (code, message string) {
	var e struct {
		Error struct {
			Status  string `json:"status"`
			Message string `json:"message"`
			Details []struct {
				Type      string `json:"@type"`
				ErrorCode string `json:"errorCode"`
			} `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &e) != nil {
		return "", strings.TrimSpace(string(raw))
	}
	for _, d := range e.Error.Details {
		if strings.HasSuffix(d.Type, "google.firebase.fcm.v1.FcmError") && d.ErrorCode != "" {
			return d.ErrorCode, e.Error.Message
		}
	}
	return e.Error.Status, e.Error.Message
}

func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.token != "" && time.Now().Before(c.until) {
		t := c.token
		c.mu.Unlock()
		return t, nil
	}
	c.mu.Unlock()
	now := time.Now()
	assertion, err := c.sign(map[string]any{"iss": c.email, "scope": Scope,
		"aud": c.tokenURI, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURI, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", transientError{fmt.Errorf("fcm token: %w", err)}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode >= 500 {
		return "", transientError{fmt.Errorf("fcm token: HTTP %d", resp.StatusCode)}
	}
	if resp.StatusCode != http.StatusOK {
		// A revoked key or missing role: retrying will not help.
		return "", fmt.Errorf("fcm token: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
		return "", errors.New("fcm token: bad response")
	}
	c.mu.Lock()
	c.token, c.until = out.AccessToken, now.Add(time.Duration(out.ExpiresIn)*time.Second-time.Minute)
	c.mu.Unlock()
	return out.AccessToken, nil
}

func (c *Client) sign(claims map[string]any) (string, error) {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := header + "." + enc.EncodeToString(payload)
	sum := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + enc.EncodeToString(sig), nil
}
