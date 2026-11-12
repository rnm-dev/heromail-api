// Package meet creates Google Meet rooms for calendar events through the Meet
// REST API, acting as the organizer via a Google Workspace service account
// with domain-wide delegation. Stdlib only: the JWT bearer grant is small.
package meet

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
	"strings"
	"sync"
	"time"
)

// Scope lets the service account create spaces and manage only those.
const Scope = "https://www.googleapis.com/auth/meetings.space.created"

var (
	// ErrNotConfigured means GOOGLE_MEET_CREDENTIALS is unset.
	ErrNotConfigured = errors.New("google meet is not configured")
	// ErrNoGoogleAccount means neither the organizer nor the fallback host
	// could be impersonated (not a Google Workspace user, or delegation missing).
	ErrNoGoogleAccount = errors.New("no Google account to host the meeting")
)

// Space is a created meeting room.
type Space struct {
	URL  string `json:"url"`
	Code string `json:"code"`
	// Host is the Google account that owns the room: the organizer, or the
	// fallback host when the organizer has no Google account.
	Host string `json:"host"`
}

type Client struct {
	email, tokenURI, fallback string
	key                       *rsa.PrivateKey
	http                      *http.Client
	apiURL                    string

	mu     sync.Mutex
	tokens map[string]token
}

type token struct {
	value string
	until time.Time
}

// FromEnv reads GOOGLE_MEET_CREDENTIALS (path to the service account JSON key)
// and the optional GOOGLE_MEET_FALLBACK_USER (a Workspace user hosting rooms
// for organizers without a Google account).
func FromEnv() (*Client, error) {
	path := os.Getenv("GOOGLE_MEET_CREDENTIALS")
	if path == "" {
		return nil, ErrNotConfigured
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read credentials: %w", err)
	}
	return New(raw, os.Getenv("GOOGLE_MEET_FALLBACK_USER"))
}

// New parses a service account JSON key.
func New(credentials []byte, fallback string) (*Client, error) {
	var sa struct {
		Type        string `json:"type"`
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
	if sa.TokenURI == "" {
		sa.TokenURI = "https://oauth2.googleapis.com/token"
	}
	return &Client{email: sa.ClientEmail, tokenURI: sa.TokenURI, key: key,
		fallback: strings.ToLower(strings.TrimSpace(fallback)),
		http:     &http.Client{Timeout: 15 * time.Second}, apiURL: "https://meet.googleapis.com/v2",
		tokens: map[string]token{}}, nil
}

// CreateSpace creates a room owned by organizer, or by the fallback host when
// the organizer cannot be impersonated.
func (c *Client) CreateSpace(ctx context.Context, organizer string) (Space, error) {
	hosts := []string{strings.ToLower(strings.TrimSpace(organizer))}
	if c.fallback != "" && c.fallback != hosts[0] {
		hosts = append(hosts, c.fallback)
	}
	var last error
	for _, host := range hosts {
		tok, err := c.token(ctx, host)
		if errors.Is(err, errDenied) {
			last = err
			continue
		}
		if err != nil {
			return Space{}, err
		}
		space, err := c.create(ctx, tok)
		if errors.Is(err, errDenied) {
			last = err
			continue
		}
		if err != nil {
			return Space{}, err
		}
		space.Host = host
		return space, nil
	}
	return Space{}, fmt.Errorf("%w: %v", ErrNoGoogleAccount, last)
}

var errDenied = errors.New("denied")

func (c *Client) token(ctx context.Context, subject string) (string, error) {
	c.mu.Lock()
	if t, ok := c.tokens[subject]; ok && time.Now().Before(t.until) {
		c.mu.Unlock()
		return t.value, nil
	}
	c.mu.Unlock()
	now := time.Now()
	assertion, err := c.sign(map[string]any{"iss": c.email, "sub": subject, "scope": Scope,
		"aud": c.tokenURI, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURI, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("token: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// invalid_grant / unauthorized_client: unknown user or delegation not granted.
		return "", fmt.Errorf("%w: token for %s: %s", errDenied, subject, strings.TrimSpace(string(body)))
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
		return "", fmt.Errorf("token: bad response")
	}
	c.mu.Lock()
	c.tokens[subject] = token{out.AccessToken, now.Add(time.Duration(out.ExpiresIn)*time.Second - time.Minute)}
	c.mu.Unlock()
	return out.AccessToken, nil
}

func (c *Client) create(ctx context.Context, tok string) (Space, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.apiURL+"/spaces", bytes.NewReader([]byte("{}")))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := c.http.Do(req)
	if err != nil {
		return Space{}, fmt.Errorf("meet: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		// e.g. the user has no Meet licence.
		return Space{}, fmt.Errorf("%w: meet: %s", errDenied, strings.TrimSpace(string(body)))
	}
	if resp.StatusCode != http.StatusOK {
		return Space{}, fmt.Errorf("meet: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out struct {
		MeetingURI  string `json:"meetingUri"`
		MeetingCode string `json:"meetingCode"`
	}
	if err := json.Unmarshal(body, &out); err != nil || !strings.HasPrefix(out.MeetingURI, "https://") {
		return Space{}, errors.New("meet: bad response")
	}
	return Space{URL: out.MeetingURI, Code: out.MeetingCode}, nil
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
