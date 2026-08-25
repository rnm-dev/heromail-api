// Package auth authenticates API requests by workspace API key.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/rnm/heromail/backend/internal/apikey"
)

type contextKey int

const (
	workspaceIDKey contextKey = iota
	apiKeyIDKey
)

// WorkspaceID returns the workspace the request authenticated as. It is
// present on every request that made it past Middleware.
func WorkspaceID(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(workspaceIDKey).(string)
	return id, ok
}

// WithWorkspaceID returns a copy of r carrying workspaceID, exactly as
// Middleware would have set it. It exists so handlers can be tested without
// standing up authentication.
func WithWorkspaceID(r *http.Request, workspaceID string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), workspaceIDKey, workspaceID))
}

// APIKeyID returns the id of the key that authenticated the request, for audit
// logging.
func APIKeyID(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(apiKeyIDKey).(string)
	return id, ok
}

// touchInterval throttles last_used_at writes. Stamping it on every request
// would mean a row update per API call — pure write amplification for a field
// nobody reads at that resolution.
const touchInterval = time.Minute

// Authenticator resolves API keys against the database.
type Authenticator struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Authenticator {
	return &Authenticator{pool: pool}
}

// Middleware rejects any request without a live API key. On success the
// workspace id is in the request context, which is what scopes every
// downstream query.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, err := bearerToken(r.Header.Get("Authorization"))
		if err != nil {
			unauthorized(w, err.Error())
			return
		}

		workspaceID, keyID, lastUsed, err := a.lookup(r.Context(), key)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			// Unknown, revoked and malformed keys are one answer on purpose:
			// the caller learns nothing about which keys exist.
			unauthorized(w, "invalid or revoked API key")
			return
		case err != nil:
			log.Printf("auth: key lookup failed: %v", err)
			writeError(w, http.StatusInternalServerError, "internal",
				"authentication is temporarily unavailable")
			return
		}

		if lastUsed == nil || time.Since(*lastUsed) > touchInterval {
			a.touch(r.Context(), keyID)
		}

		ctx := context.WithValue(r.Context(), workspaceIDKey, workspaceID)
		ctx = context.WithValue(ctx, apiKeyIDKey, keyID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *Authenticator) lookup(ctx context.Context, key string) (workspaceID, keyID string, lastUsed *time.Time, err error) {
	err = a.pool.QueryRow(ctx, `
		SELECT workspace_id, id, last_used_at
		FROM api_keys
		WHERE key_hash = $1 AND revoked_at IS NULL`,
		apikey.Hash(key),
	).Scan(&workspaceID, &keyID, &lastUsed)
	return workspaceID, keyID, lastUsed, err
}

// touch records that the key was used. A failure here must not fail the
// request: the caller authenticated successfully, and last_used_at is
// bookkeeping.
func (a *Authenticator) touch(ctx context.Context, keyID string) {
	// WithoutCancel: the update outlives the response, and losing it because
	// the client hung up would be silly.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()

	if _, err := a.pool.Exec(ctx,
		`UPDATE api_keys SET last_used_at = now() WHERE id = $1`, keyID,
	); err != nil {
		log.Printf("auth: touch last_used_at for %s: %v", keyID, err)
	}
}

// bearerToken pulls the key out of an Authorization header.
func bearerToken(header string) (string, error) {
	if strings.TrimSpace(header) == "" {
		return "", errors.New("missing Authorization header")
	}

	scheme, value, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", errors.New(`Authorization header must be "Bearer <key>"`)
	}

	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("empty bearer token")
	}
	return value, nil
}

func unauthorized(w http.ResponseWriter, msg string) {
	// RFC 9110: a 401 has to say how to authenticate.
	w.Header().Set("WWW-Authenticate", `Bearer realm="heromail"`)
	writeError(w, http.StatusUnauthorized, "unauthenticated", msg)
}

// writeError emits the API-wide error envelope declared in api/openapi.yaml.
// This middleware answers before internal/httpapi is reached, so it carries its
// own copy of the shape.
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}
