-- Promote workspaces.mail_domain into a first-class domains table with an
-- ownership-verification lifecycle, plus DKIM signing keys per domain.

-- ------------------------------------------------------------------- domains

CREATE TABLE domains (
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id       uuid        NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,

    -- Globally unique, not per-workspace: a domain routes mail for exactly one
    -- tenant, so two workspaces must never both claim acme.com.
    -- Stored lowercase (the pattern enforces it), which keeps the plain unique
    -- index case-safe -- citext would defeat the lowercase CHECK, since its
    -- comparisons are case-insensitive.
    domain             text        NOT NULL UNIQUE
                                   CHECK (domain ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'),

    -- Default domain for new mailboxes in this workspace.
    is_primary         boolean     NOT NULL DEFAULT false,

    -- Value published as a DNS TXT record to prove ownership. Unlike an invite
    -- token this is *meant* to be public, so it is stored in plaintext: we have
    -- to hand the exact string back to the admin on every settings page view,
    -- and knowing it grants nothing without control of the domain's DNS.
    verification_token text        NOT NULL,
    verified_at        timestamptz,

    -- Result of the last DNS check, for showing "we looked, here is what broke".
    last_checked_at    timestamptz,
    last_error         text,

    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),

    -- An unverified domain must not become the workspace default.
    CHECK (NOT is_primary OR verified_at IS NOT NULL)
);

-- At most one primary domain per workspace.
CREATE UNIQUE INDEX domains_one_primary
    ON domains (workspace_id)
    WHERE is_primary;

CREATE INDEX domains_workspace_id ON domains (workspace_id);

CREATE TRIGGER domains_set_updated_at
    BEFORE UPDATE ON domains
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Carry over any existing workspaces.mail_domain as an already-verified primary.
INSERT INTO domains (workspace_id, domain, is_primary, verification_token, verified_at)
SELECT id,
       lower(mail_domain::text),
       true,
       encode(sha256((id::text || clock_timestamp()::text)::bytea), 'hex'),
       now()
FROM workspaces
WHERE mail_domain IS NOT NULL;

ALTER TABLE workspaces DROP COLUMN mail_domain;

-- ----------------------------------------------------------------- dkim_keys

-- Outbound mail is DKIM-signed per domain. Rotation needs the old key to stay
-- published until every in-flight message verifies, so a domain holds several
-- keys at once and exactly one signs.
CREATE TABLE dkim_keys (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id   uuid        NOT NULL REFERENCES domains (id) ON DELETE CASCADE,

    -- DNS label: <selector>._domainkey.<domain>
    selector    text        NOT NULL CHECK (selector ~ '^[a-z0-9][a-z0-9-]{0,62}$'),

    public_key  text        NOT NULL,
    -- Encrypted by the application before it ever reaches this column; the
    -- database never sees the raw private key.
    private_key text        NOT NULL,

    is_active   boolean     NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now(),
    retired_at  timestamptz,

    UNIQUE (domain_id, selector),
    -- A retired key cannot be the signing key.
    CHECK (NOT is_active OR retired_at IS NULL)
);

-- Exactly one signing key per domain; rotation retires the old and activates
-- the new in one transaction.
CREATE UNIQUE INDEX dkim_keys_one_active
    ON dkim_keys (domain_id)
    WHERE is_active;

CREATE INDEX dkim_keys_domain_id ON dkim_keys (domain_id);
