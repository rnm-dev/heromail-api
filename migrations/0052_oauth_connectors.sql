-- OAuth for remote MCP connectors (claude.ai and similar). See docs/mcp.md.
--
-- A client registers itself (RFC 7591), the user approves it for one mailbox
-- they own, and the client gets short access tokens plus a rotating refresh
-- token. Every MCP request re-checks the same ownership rule as assistant
-- keys, so reassignment, leaving the workspace or an unverified domain cut
-- access at once; a revoked grant kills all of its tokens.
CREATE TABLE oauth_clients (
    id            text PRIMARY KEY,
    name          text NOT NULL,
    redirect_uris text[] NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE oauth_codes (
    code_hash      bytea PRIMARY KEY,
    client_id      text NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mailbox_id     uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    redirect_uri   text NOT NULL,
    code_challenge text NOT NULL,
    expires_at     timestamptz NOT NULL
);

CREATE TABLE oauth_grants (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id    text NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mailbox_id   uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz
);
CREATE INDEX oauth_grants_user ON oauth_grants(user_id);

CREATE TABLE oauth_tokens (
    token_hash bytea PRIMARY KEY,
    grant_id   uuid NOT NULL REFERENCES oauth_grants(id) ON DELETE CASCADE,
    kind       text NOT NULL CHECK (kind IN ('access', 'refresh')),
    expires_at timestamptz NOT NULL
);
CREATE INDEX oauth_tokens_grant ON oauth_tokens(grant_id);
