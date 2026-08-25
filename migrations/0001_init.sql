-- Core tenancy model: workspaces, users, membership roles, invites.

CREATE EXTENSION IF NOT EXISTS citext;

-- Role inside a single workspace. Ordered from most to least privileged.
CREATE TYPE workspace_role AS ENUM ('owner', 'admin', 'member');

CREATE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------- workspaces

CREATE TABLE workspaces (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Slug is the tenant handle used in URLs. Lowercase is enforced by the
    -- pattern itself, so a plain unique index is already case-safe.
    slug        text        NOT NULL UNIQUE
                            CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$'),
    name        text        NOT NULL CHECK (btrim(name) <> ''),
    -- Mail domain the workspace owns, e.g. 'acme.com'. Nullable until verified.
    mail_domain citext      UNIQUE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER workspaces_set_updated_at
    BEFORE UPDATE ON workspaces
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- --------------------------------------------------------------------- users

-- Identity is global, not per-workspace: one person, one login, many
-- workspaces. Membership lives in workspace_members.
CREATE TABLE users (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    email         citext      NOT NULL UNIQUE CHECK (email LIKE '%_@_%'),
    name          text        NOT NULL DEFAULT '',
    -- NULL for users who authenticate through SSO only.
    password_hash text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER users_set_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- --------------------------------------------------------- workspace_members

CREATE TABLE workspace_members (
    workspace_id uuid           NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    user_id      uuid           NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role         workspace_role NOT NULL DEFAULT 'member',
    created_at   timestamptz    NOT NULL DEFAULT now(),
    updated_at   timestamptz    NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, user_id)
);

-- At most one owner per workspace. Transferring ownership therefore has to
-- demote the current owner and promote the new one in the same transaction.
CREATE UNIQUE INDEX workspace_members_one_owner
    ON workspace_members (workspace_id)
    WHERE role = 'owner';

-- "Which workspaces does this user belong to?"
CREATE INDEX workspace_members_user_id ON workspace_members (user_id);

CREATE TRIGGER workspace_members_set_updated_at
    BEFORE UPDATE ON workspace_members
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ------------------------------------------------------------------- invites

CREATE TABLE invites (
    id           uuid           PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id uuid           NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,
    email        citext         NOT NULL CHECK (email LIKE '%_@_%'),
    role         workspace_role NOT NULL DEFAULT 'member',
    -- SHA-256 of the token. The plaintext token is shown once, at creation, and
    -- never stored: a leaked table dump must not grant workspace access.
    token_hash   bytea          NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    invited_by   uuid           REFERENCES users (id) ON DELETE SET NULL,
    expires_at   timestamptz    NOT NULL,
    accepted_at  timestamptz,
    accepted_by  uuid           REFERENCES users (id) ON DELETE SET NULL,
    revoked_at   timestamptz,
    created_at   timestamptz    NOT NULL DEFAULT now(),

    -- An invite cannot be both accepted and revoked.
    CHECK (accepted_at IS NULL OR revoked_at IS NULL),
    -- Accepted invites must record who accepted them.
    CHECK ((accepted_at IS NULL) = (accepted_by IS NULL))
);

-- Status is derived, not stored: pending = both timestamps NULL and not past
-- expires_at. This index enforces one live invite per email per workspace while
-- still allowing a fresh invite after a revoke.
CREATE UNIQUE INDEX invites_one_pending_per_email
    ON invites (workspace_id, email)
    WHERE accepted_at IS NULL AND revoked_at IS NULL;

CREATE INDEX invites_workspace_id ON invites (workspace_id);
CREATE INDEX invites_email ON invites (email);
