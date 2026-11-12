-- Mobile sessions: a device-bound session whose bearer token is short-lived
-- and renewed with a rotating refresh token (see docs/mobile-api.md).
--
-- A web session is unchanged: client = 'web', access_expires_at IS NULL, and
-- its bearer token lives until expires_at, exactly as before.

CREATE TYPE session_client AS ENUM ('web', 'ios', 'android');

ALTER TABLE sessions
    ADD COLUMN client            session_client NOT NULL DEFAULT 'web',
    ADD COLUMN device_name       text CHECK (char_length(device_name) <= 200),
    ADD COLUMN app_version       text CHECK (char_length(app_version) <= 50),
    -- When the current bearer token stops working. NULL for web sessions,
    -- whose token is good for the whole session (expires_at).
    ADD COLUMN access_expires_at timestamptz;

-- "Your devices" lists one user's live sessions, newest activity first.
CREATE INDEX sessions_user_live ON sessions (user_id, last_seen_at DESC)
    WHERE revoked_at IS NULL;

-- One row per refresh token ever issued for a session. Rotation marks the
-- presented row used and inserts its successor, so the rows of one session are
-- the chain. Presenting a used token again is the reuse signal: the session —
-- and with it every token in the chain — is revoked.
CREATE TABLE session_refresh_tokens (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id uuid        NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    token_hash bytea       NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX session_refresh_tokens_session_id ON session_refresh_tokens (session_id);
