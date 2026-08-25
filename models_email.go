package main

import "time"

// APIKey authenticates machine access to a workspace. Only the digest and a
// display prefix are stored; see internal/apikey.
//
// Email, its status and its events used to live here too; they moved to
// internal/email, the layer that owns them.
type APIKey struct {
	ID          string     `json:"id"`
	WorkspaceID string     `json:"workspace_id"`
	Name        string     `json:"name"`
	KeyPrefix   string     `json:"key_prefix"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	RevokedAt   *time.Time `json:"revoked_at"`
	CreatedAt   time.Time  `json:"created_at"`
}

// Active reports whether the key may still authenticate.
func (k APIKey) Active() bool { return k.RevokedAt == nil }
