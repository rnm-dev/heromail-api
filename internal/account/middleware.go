package account

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// writeError emits the API-wide error envelope. The HTTP surface lives in
// internal/httpapi, but this middleware answers before that layer is reached,
// so it needs its own copy of the shape the spec declares.
func writeError(w http.ResponseWriter, status int, code, message string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="heromail"`)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}

type contextKey int

const (
	userKey contextKey = iota
	sessionTokenKey
)

// CurrentUser returns the signed-in user. Present on every request that made
// it past RequireSession.
func CurrentUser(ctx context.Context) (*User, bool) {
	u, ok := ctx.Value(userKey).(*User)
	return u, ok
}

// SessionToken returns the raw token the request authenticated with, so logout
// can revoke exactly this session.
func SessionToken(ctx context.Context) (string, bool) {
	t, ok := ctx.Value(sessionTokenKey).(string)
	return t, ok
}

// WithUser injects a user as RequireSession would, for tests.
func WithUser(r *http.Request, u *User) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), userKey, u))
}

// touchInterval throttles last_seen_at writes, for the same reason as API keys.
const touchInterval = 5 * time.Minute

// RequireSession rejects requests without a live session cookie-equivalent
// bearer token.
func (s *Service) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, err := bearerToken(r.Header.Get("Authorization"))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthenticated", err.Error())
			return
		}

		user, sessionID, lastSeen, err := s.store.UserBySessionToken(r.Context(), hashToken(token))
		switch {
		case errors.Is(err, ErrNotFound):
			writeError(w, http.StatusUnauthorized, "unauthenticated", "session is invalid or expired")
			return
		case err != nil:
			log.Printf("account: session lookup: %v", err)
			writeError(w, http.StatusInternalServerError, "internal", "authentication is temporarily unavailable")
			return
		}

		if user.MustChangePassword && r.URL.Path != "/auth/me" && r.URL.Path != "/auth/logout" && r.URL.Path != "/auth/change-initial-password" {
			writeError(w, http.StatusForbidden, "password_change_required", "Сначала задайте собственный пароль.")
			return
		}
		if lastSeen == nil || time.Since(*lastSeen) > touchInterval {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 3*time.Second)
			if err := s.store.TouchSession(ctx, sessionID); err != nil {
				log.Printf("account: touch session %s: %v", sessionID, err)
			}
			cancel()
		}

		ctx := context.WithValue(r.Context(), userKey, user)
		ctx = context.WithValue(ctx, sessionTokenKey, token)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func bearerToken(header string) (string, error) {
	if strings.TrimSpace(header) == "" {
		return "", errors.New("missing Authorization header")
	}
	scheme, value, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", errors.New(`Authorization header must be "Bearer <token>"`)
	}
	if value = strings.TrimSpace(value); value == "" {
		return "", errors.New("empty bearer token")
	}
	return value, nil
}

// clientIP prefers the address nginx forwarded, falling back to the socket.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if first, _, found := strings.Cut(xff, ","); found {
			return strings.TrimSpace(first)
		}
		return strings.TrimSpace(xff)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
