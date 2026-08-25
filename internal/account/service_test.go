package account

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rnm/heromail/backend/internal/provider"
)

// Service-level tests. The HTTP surface is generated from api/openapi.yaml and
// tested in internal/httpapi; what lives here is the logic underneath it.

type fakeSender struct {
	mu   sync.Mutex
	sent []provider.Message
}

func (f *fakeSender) Send(_ context.Context, msg provider.Message) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, msg)
	return "fake@heromail.local", nil
}

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL is not set; skipping database-backed account tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestExternalIdentityFlow exercises the path every future SSO provider takes,
// without any provider being implemented: build an ExternalIdentity, hand it to
// the service, and the rest of the stack behaves.
func TestExternalIdentityFlow(t *testing.T) {
	pool := testPool(t)
	store := NewStore(pool)
	svc := NewService(store, &fakeSender{}, Config{AppBaseURL: "https://app.test"})
	ctx := context.Background()

	addr := fmt.Sprintf("sso-%d@acme.test", time.Now().UnixNano())
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM users WHERE email = $1`, addr)
	})

	ext := ExternalIdentity{
		Provider:      ProviderGoogle,
		Subject:       fmt.Sprintf("google-sub-%d", time.Now().UnixNano()),
		Email:         addr,
		Name:          "SSO User",
		EmailVerified: true,
	}

	// First sign-in creates the user, already verified — Google vouched.
	first, err := svc.SignInWithIdentity(ctx, ext, RequestContext{})
	if err != nil {
		t.Fatalf("first SSO sign-in: %v", err)
	}
	if !first.User.EmailVerified() {
		t.Error("a provider-verified address should land verified")
	}

	// Second sign-in reuses the same user rather than creating another.
	second, err := svc.SignInWithIdentity(ctx, ext, RequestContext{})
	if err != nil {
		t.Fatalf("second SSO sign-in: %v", err)
	}
	if first.User.ID != second.User.ID {
		t.Errorf("same subject produced two users: %s vs %s", first.User.ID, second.User.ID)
	}
	if first.Token == second.Token {
		t.Error("each sign-in must mint a distinct session token")
	}

	// A different provider with the same verified address links to that user.
	entra := ExternalIdentity{
		Provider:      ProviderMicrosoft,
		Subject:       fmt.Sprintf("entra-oid-%d", time.Now().UnixNano()),
		Email:         addr,
		EmailVerified: true,
	}
	linked, err := svc.SignInWithIdentity(ctx, entra, RequestContext{})
	if err != nil {
		t.Fatalf("linking a second provider: %v", err)
	}
	if linked.User.ID != first.User.ID {
		t.Error("a verified address should link, not fork the account")
	}

	var identities int
	pool.QueryRow(ctx, `SELECT count(*) FROM identities WHERE user_id = $1`, first.User.ID).Scan(&identities)
	if identities != 2 {
		t.Errorf("user has %d identities, want 2 (google + microsoft)", identities)
	}

	// An unverified address must never auto-link: that would be account takeover.
	takeover := ExternalIdentity{
		Provider:      ProviderOIDC,
		Subject:       fmt.Sprintf("sketchy-%d", time.Now().UnixNano()),
		Email:         addr,
		EmailVerified: false,
	}
	if _, err := svc.SignInWithIdentity(ctx, takeover, RequestContext{}); err == nil {
		t.Error("an unverified claim to a taken address must not succeed")
	}

	// Password is not an external provider.
	if _, err := svc.SignInWithIdentity(ctx, ExternalIdentity{
		Provider: ProviderPassword, Subject: "x",
	}, RequestContext{}); err == nil {
		t.Error("password must be rejected as an external provider")
	}
}

func TestPasswordHashingRoundTrip(t *testing.T) {
	hash, err := hashPassword("correct-horse-battery")
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if strings.Contains(string(hash), "correct-horse") {
		t.Fatal("the hash contains the password")
	}
	if !verifyPassword(hash, "correct-horse-battery") {
		t.Error("the correct password did not verify")
	}
	if verifyPassword(hash, "correct-horse-batteru") {
		t.Error("a wrong password verified")
	}

	if _, err := hashPassword("short"); err == nil {
		t.Error("a short password was accepted")
	}
	if _, err := hashPassword(strings.Repeat("a", 73)); err == nil {
		t.Error("a password past bcrypt's 72-byte limit was accepted")
	}
}

func TestBearerToken(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
		wantOK bool
	}{
		{"valid", "Bearer tok", "tok", true},
		{"lowercase scheme", "bearer tok", "tok", true},
		{"padded value", "Bearer   tok  ", "tok", true},
		{"missing header", "", "", false},
		{"wrong scheme", "Basic aGk6dGhlcmU=", "", false},
		{"bare token", "tok", "", false},
		{"empty token", "Bearer ", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := bearerToken(tc.header)
			if tc.wantOK != (err == nil) {
				t.Fatalf("bearerToken(%q) error = %v, wantOK = %v", tc.header, err, tc.wantOK)
			}
			if got != tc.want {
				t.Errorf("bearerToken(%q) = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}
