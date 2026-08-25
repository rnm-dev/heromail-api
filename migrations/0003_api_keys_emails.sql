-- Sending surface: API keys, the outbound email log, and its event trail.
-- Everything is workspace-scoped and disappears with the workspace.

CREATE TYPE email_status AS ENUM ('queued', 'processing', 'sent', 'failed', 'dead');

CREATE TYPE email_event_type AS ENUM (
    'queued', 'processing', 'sent', 'failed', 'bounced', 'complained', 'delivered'
);

-- ------------------------------------------------------------------ api_keys

CREATE TABLE api_keys (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid        NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    name         text        NOT NULL CHECK (btrim(name) <> ''),

    -- SHA-256 of the full key, same treatment as invites.token_hash: the
    -- plaintext is shown once at creation and never stored.
    key_hash     bytea       NOT NULL UNIQUE CHECK (octet_length(key_hash) = 32),

    -- Leading characters of the key ('hm_live_a1b2'), kept so the UI can
    -- identify a key in a list without holding anything usable.
    key_prefix   text        NOT NULL CHECK (btrim(key_prefix) <> ''),

    last_used_at timestamptz,
    revoked_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX api_keys_workspace_id ON api_keys (workspace_id);

-- -------------------------------------------------------------------- emails

CREATE TABLE emails (
    id                  uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id        uuid         NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,

    from_addr           citext       NOT NULL CHECK (from_addr LIKE '%_@_%'),
    -- Recipient list denormalised onto the send record; see docs/data-model.md
    -- for why this is an array rather than its own table.
    -- cardinality(), not array_length(): array_length of an empty array is
    -- NULL, and a CHECK that evaluates to NULL passes, so '{}' would slip
    -- through. cardinality() returns 0 and the constraint bites.
    to_addrs            text[]       NOT NULL
                                     CHECK (cardinality(to_addrs) >= 1)
                                     CHECK (array_position(to_addrs, NULL) IS NULL)
                                     CHECK (array_position(to_addrs, '') IS NULL),

    subject             text         NOT NULL DEFAULT '',
    html_body           text,
    text_body           text,

    status              email_status NOT NULL DEFAULT 'queued',

    -- Identifier returned by the upstream MTA/provider once handed off.
    provider_message_id text,

    -- Caller-supplied dedup key; scoped to the workspace, never global.
    idempotency_key     text,

    attempts            int          NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error          text,

    created_at          timestamptz  NOT NULL DEFAULT now(),
    updated_at          timestamptz  NOT NULL DEFAULT now(),

    -- A message with neither body is not a message.
    CHECK (coalesce(btrim(html_body), '') <> '' OR coalesce(btrim(text_body), '') <> '')
);

-- Retrying a send with the same idempotency key must hit the same row, but only
-- within one workspace: two tenants may independently use the key 'order-1'.
-- Partial, so the unlimited number of rows without a key stay unconstrained.
CREATE UNIQUE INDEX emails_workspace_idempotency_key
    ON emails (workspace_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;

-- Backs the per-workspace activity log, newest first.
CREATE INDEX emails_workspace_created_at
    ON emails (workspace_id, created_at DESC);

CREATE TRIGGER emails_set_updated_at
    BEFORE UPDATE ON emails
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- -------------------------------------------------------------- email_events

-- Append-only trail of what happened to a message. Scoped to the workspace
-- transitively through emails, which is what makes the cascade work; a second
-- workspace_id column here could drift out of step with emails.workspace_id.
CREATE TABLE email_events (
    id         uuid             PRIMARY KEY DEFAULT gen_random_uuid(),
    email_id   uuid             NOT NULL REFERENCES emails (id) ON DELETE CASCADE,
    type       email_event_type NOT NULL,
    -- Raw provider payload: bounce codes, diagnostic text, webhook body.
    detail     jsonb,
    created_at timestamptz      NOT NULL DEFAULT now()
);

CREATE INDEX email_events_email_id_created_at ON email_events (email_id, created_at);
