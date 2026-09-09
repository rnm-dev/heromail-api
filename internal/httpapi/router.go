package httpapi

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/rnm/heromail/backend/internal/account"
	"github.com/rnm/heromail/backend/internal/auth"
)

// writeErrorEnvelope emits the error shape from api/openapi.yaml for replies
// generated below the operation layer, which cannot return a typed response.
func writeErrorEnvelope(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}

type ctxKey int

const requestContextKey ctxKey = iota

// Router builds the full HTTP handler: CORS, then per-prefix authentication,
// then the generated router.
//
// Authentication is applied by path prefix rather than per operation because
// the two credentials are not interchangeable — a session must not reach /v1,
// and an API key must not reach /workspaces. The prefixes mirror the `security`
// blocks in api/openapi.yaml; keep them in step.
func Router(server *Server, apiKeys *auth.Authenticator, accounts *account.Service) http.Handler {
	// The generated layer answers before our operations do — malformed JSON,
	// an unparseable path parameter, a failed operation. Left at its defaults
	// it writes plain text, which the spec does not declare; these handlers
	// keep even those replies inside the error envelope.
	strict := NewStrictHandlerWithOptions(server, nil, StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			writeErrorEnvelope(w, http.StatusBadRequest, "invalid_request", err.Error())
		},
		ResponseErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			log.Printf("httpapi: %v", err)
			writeErrorEnvelope(w, http.StatusInternalServerError, "internal", "internal server error")
		},
	})

	generated := HandlerWithOptions(strict, StdHTTPServerOptions{
		BaseRouter: http.NewServeMux(),
		ErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			writeErrorEnvelope(w, http.StatusBadRequest, "invalid_request", err.Error())
		},
	})

	sessionGuarded := accounts.RequireSession(generated)
	apiKeyGuarded := apiKeys.Middleware(generated)

	root := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasPrefix(path, "/v1/"):
			apiKeyGuarded.ServeHTTP(w, r)
		case path == "/workspaces" || strings.HasPrefix(path, "/workspaces/"),
			path == "/auth/change-initial-password", path == "/auth/me", path == "/auth/logout", path == "/messages/search":
			sessionGuarded.ServeHTTP(w, r)
		default:
			// /health and the public /auth/* endpoints.
			generated.ServeHTTP(w, r)
		}
	})

	return cors(withRequestContext(root))
}

// withRequestContext stashes the user agent and client IP, which the session
// store records but the generated operations cannot reach: strict handlers
// receive a context, not the request.
func withRequestContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := account.RequestContext{
			UserAgent: r.Header.Get("User-Agent"),
			IP:        clientIP(r),
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestContextKey, rc)))
	})
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

func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Idempotency-Key")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
