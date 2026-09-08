package httpapi

import (
	"context"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/rnm/heromail/backend/internal/apikey"
	"github.com/rnm/heromail/backend/internal/workspace"
)

// API keys were issuable only by running a command on the server, which meant
// a customer could not get one without asking us. Reading the list needs
// membership; minting and revoking need admin, because a key is a credential
// for the whole workspace.

type apiKeyRow struct {
	ID         string
	Name       string
	KeyPrefix  string
	LastUsedAt *time.Time
	RevokedAt  *time.Time
	CreatedAt  time.Time
}

func (s *Server) ListApiKeys(ctx context.Context, request ListApiKeysRequestObject) (ListApiKeysResponseObject, error) {
	workspaceID, _, err := s.scope(ctx, string(request.Slug), workspace.RoleMember)
	if err != nil {
		return ListApiKeys404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "workspace not found"))}, nil
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, name, key_prefix, last_used_at, revoked_at, created_at
		FROM api_keys WHERE workspace_id = $1 ORDER BY created_at DESC`, workspaceID)
	if err != nil {
		log.Printf("list api keys: %v", err)
		return nil, err
	}
	defer rows.Close()

	out := make([]ApiKey, 0)
	for rows.Next() {
		var k apiKeyRow
		if err := rows.Scan(&k.ID, &k.Name, &k.KeyPrefix, &k.LastUsedAt, &k.RevokedAt, &k.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, apiKeyToAPI(k))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ListApiKeys200JSONResponse{ApiKeys: out}, nil
}

func (s *Server) CreateApiKey(ctx context.Context, request CreateApiKeyRequestObject) (CreateApiKeyResponseObject, error) {
	workspaceID, forbidden, err := s.scope(ctx, string(request.Slug), workspace.RoleAdmin)
	if err != nil {
		return CreateApiKey404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "workspace not found"))}, nil
	}
	if forbidden {
		return CreateApiKey403JSONResponse{ForbiddenJSONResponse(errorBody("forbidden", "admin role required"))}, nil
	}
	if request.Body == nil || strings.TrimSpace(request.Body.Name) == "" {
		return CreateApiKey400JSONResponse{BadRequestJSONResponse(errorBody("validation_failed", "name is required"))}, nil
	}

	key, prefix, hash, err := apikey.New()
	if err != nil {
		log.Printf("generate api key: %v", err)
		return nil, err
	}

	var row apiKeyRow
	err = s.pool.QueryRow(ctx, `
		INSERT INTO api_keys (workspace_id, name, key_hash, key_prefix)
		VALUES ($1, $2, $3, $4)
		RETURNING id, name, key_prefix, last_used_at, revoked_at, created_at`,
		workspaceID, strings.TrimSpace(request.Body.Name), hash, prefix,
	).Scan(&row.ID, &row.Name, &row.KeyPrefix, &row.LastUsedAt, &row.RevokedAt, &row.CreatedAt)
	if err != nil {
		log.Printf("create api key: %v", err)
		return nil, err
	}

	// The only time the plaintext exists outside the caller: only its digest
	// was stored, so there is no way to show it again.
	return CreateApiKey201JSONResponse{
		Id:         mustUUID(row.ID),
		Name:       row.Name,
		KeyPrefix:  row.KeyPrefix,
		LastUsedAt: row.LastUsedAt,
		RevokedAt:  row.RevokedAt,
		CreatedAt:  row.CreatedAt,
		Key:        key,
	}, nil
}

func (s *Server) RevokeApiKey(ctx context.Context, request RevokeApiKeyRequestObject) (RevokeApiKeyResponseObject, error) {
	workspaceID, forbidden, err := s.scope(ctx, string(request.Slug), workspace.RoleAdmin)
	if err != nil {
		return RevokeApiKey404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "workspace not found"))}, nil
	}
	if forbidden {
		return RevokeApiKey403JSONResponse{ForbiddenJSONResponse(errorBody("forbidden", "admin role required"))}, nil
	}

	// Stamped rather than deleted: the key that signed past sends stays
	// identifiable in the log after it stops working.
	var id string
	err = s.pool.QueryRow(ctx, `
		UPDATE api_keys SET revoked_at = coalesce(revoked_at, now())
		WHERE id = $1 AND workspace_id = $2 RETURNING id`,
		request.KeyId, workspaceID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return RevokeApiKey404JSONResponse{NotFoundJSONResponse(errorBody("not_found", "api key not found"))}, nil
	}
	if err != nil {
		log.Printf("revoke api key: %v", err)
		return nil, err
	}
	return RevokeApiKey204Response{}, nil
}

func apiKeyToAPI(k apiKeyRow) ApiKey {
	return ApiKey{
		Id:         mustUUID(k.ID),
		Name:       k.Name,
		KeyPrefix:  k.KeyPrefix,
		LastUsedAt: k.LastUsedAt,
		RevokedAt:  k.RevokedAt,
		CreatedAt:  k.CreatedAt,
	}
}
