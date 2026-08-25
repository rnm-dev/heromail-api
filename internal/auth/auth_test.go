package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rnm/heromail/backend/internal/apikey"
)

func TestBearerToken(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
		wantOK bool
	}{
		{"valid", "Bearer hm_live_abc", "hm_live_abc", true},
		{"lowercase scheme", "bearer hm_live_abc", "hm_live_abc", true},
		{"padded value", "Bearer   hm_live_abc  ", "hm_live_abc", true},
		{"missing header", "", "", false},
		{"blank header", "   ", "", false},
		{"wrong scheme", "Basic aGk6dGhlcmU=", "", false},
		{"bare key", "hm_live_abc", "", false},
		{"scheme only", "Bearer", "", false},
		{"empty token", "Bearer ", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := bearerToken(tc.header)
			if tc.wantOK && err != nil {
				t.Fatalf("bearerToken(%q) returned %v", tc.header, err)
			}
			if !tc.wantOK && err == nil {
				t.Fatalf("bearerToken(%q) should have failed, got %q", tc.header, got)
			}
			if got != tc.want {
				t.Errorf("bearerToken(%q) = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}

// testPool connects to the dev database, or skips. The middleware's whole job
// is a database lookup, so a meaningful test needs one.
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL is not set; skipping database-backed auth tests")
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

// seedKey creates a throwaway workspace and one API key, and removes both
// afterwards so the dev database is left as it was found.
func seedKey(t *testing.T, pool *pgxpool.Pool, slug string, revoked bool) string {
	t.Helper()
	ctx := context.Background()

	var workspaceID string
	err := pool.QueryRow(ctx,
		`INSERT INTO workspaces (slug, name) VALUES ($1, $2) RETURNING id`,
		slug, "Auth test "+slug,
	).Scan(&workspaceID)
	if err != nil {
		t.Fatalf("seed workspace: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM workspaces WHERE id = $1`, workspaceID)
	})

	key, prefix, hash, err := apikey.New()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	revokedAt := "NULL"
	if revoked {
		revokedAt = "now()"
	}
	_, err = pool.Exec(ctx, `
		INSERT INTO api_keys (workspace_id, name, key_hash, key_prefix, revoked_at)
		VALUES ($1, $2, $3, $4, `+revokedAt+`)`,
		workspaceID, "test key", hash, prefix)
	if err != nil {
		t.Fatalf("seed api key: %v", err)
	}

	return key
}

func TestMiddleware(t *testing.T) {
	pool := testPool(t)
	a := New(pool)

	var seenWorkspace string
	handler := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenWorkspace, _ = WorkspaceID(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	liveKey := seedKey(t, pool, "authtest-live", false)
	revokedKey := seedKey(t, pool, "authtest-revoked", true)

	cases := []struct {
		name       string
		header     string
		wantStatus int
	}{
		{"valid key", "Bearer " + liveKey, http.StatusOK},
		{"revoked key", "Bearer " + revokedKey, http.StatusUnauthorized},
		{"unknown key", "Bearer " + apikey.Prefix + "0000deadbeef", http.StatusUnauthorized},
		{"no header", "", http.StatusUnauthorized},
		{"wrong scheme", "Basic zzz", http.StatusUnauthorized},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seenWorkspace = ""

			req := httptest.NewRequest(http.MethodGet, "/v1/workspace", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tc.wantStatus, rec.Body)
			}

			if tc.wantStatus == http.StatusOK {
				if seenWorkspace == "" {
					t.Error("handler ran without a workspace id in context")
				}
				return
			}

			// A 401 must not leak whether the key exists, and must say how to
			// authenticate.
			if got := rec.Header().Get("WWW-Authenticate"); got == "" {
				t.Error("401 is missing the WWW-Authenticate header")
			}
			if seenWorkspace != "" {
				t.Error("handler ran despite a rejected key")
			}
		})
	}
}

func TestMiddlewareStampsLastUsedAt(t *testing.T) {
	pool := testPool(t)
	a := New(pool)

	key := seedKey(t, pool, "authtest-lastused", false)
	handler := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest(http.MethodGet, "/v1/workspace", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	var lastUsed *time.Time
	err := pool.QueryRow(context.Background(),
		`SELECT last_used_at FROM api_keys WHERE key_hash = $1`, apikey.Hash(key),
	).Scan(&lastUsed)
	if err != nil {
		t.Fatalf("read last_used_at: %v", err)
	}
	if lastUsed == nil {
		t.Fatal("last_used_at was not stamped on first use")
	}
}
