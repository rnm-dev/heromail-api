-- Human authentication: identities (password today, SSO later), sessions, and
-- single-use tokens for email verification and password reset.

-- ---------------------------------------------------------------- identities

-- How a person proves they are themselves. Adding Google, Microsoft/Entra or a
-- corporate AD later is a new enum value plus a callback route -- not a change
-- to users, sessions, or anything downstream.
CREATE TYPE identity_provider AS ENUM (
    'password',   -- email + password, verified by us
    'google',     -- Google OIDC
    'microsoft',  -- Microsoft Entra ID (Azure AD)
    'oidc',       -- generic OIDC, e.g. a customer's own IdP
    'saml',       -- SAML 2.0, still common in enterprise AD setups
    'ldap'        -- direct LDAP/Active Directory bind
);

CREATE TABLE identities (
    id            uuid              PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid              NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider      identity_provider NOT NULL,

    -- The provider's stable identifier for this person: the OIDC `sub`, the
    -- SAML NameID, the AD objectGUID. For password auth it is the email.
    -- Never the email for external providers: people change addresses, and a
    -- reused address must not silently inherit someone else's account.
    subject       text              NOT NULL CHECK (btrim(subject) <> ''),

    -- Only meaningful for provider='password'.
    password_hash text,

    -- Raw claims as received, for debugging and for mapping rules we have not
    -- invented yet (groups -> roles, tenant -> workspace).
    metadata      jsonb,

    -- When this identity last authenticated, for "you signed in with Google".
    last_login_at timestamptz,

    created_at    timestamptz       NOT NULL DEFAULT now(),
    updated_at    timestamptz       NOT NULL DEFAULT now(),

    -- One account per subject per provider.
    UNIQUE (provider, subject),

    -- A password identity has a hash; an external one never does.
    CHECK ((provider = 'password') = (password_hash IS NOT NULL))
);

-- A user may link many providers but only ever one password.
CREATE UNIQUE INDEX identities_one_password_per_user
    ON identities (user_id)
    WHERE provider = 'password';

CREATE INDEX identities_user_id ON identities (user_id);

CREATE TRIGGER identities_set_updated_at
    BEFORE UPDATE ON identities
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Move existing passwords into the new model, then retire the column.
INSERT INTO identities (user_id, provider, subject, password_hash)
SELECT id, 'password', lower(email::text), password_hash
FROM users
WHERE password_hash IS NOT NULL;

ALTER TABLE users DROP COLUMN password_hash;

-- Verification state belongs to the person, not to one identity: an address
-- proven once stays proven, whichever provider they sign in with next.
ALTER TABLE users ADD COLUMN email_verified_at timestamptz;

-- --------------------------------------------------------------- user_tokens

CREATE TYPE user_token_purpose AS ENUM ('email_verification', 'password_reset');

-- Single-use, short-lived, emailed to the address in question. Stored as a
-- SHA-256 digest for the same reason as invites and API keys: a database dump
-- must not let anyone verify an address or reset a password.
CREATE TABLE user_tokens (
    id          uuid               PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     uuid               NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    purpose     user_token_purpose NOT NULL,
    token_hash  bytea              NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    expires_at  timestamptz        NOT NULL,
    consumed_at timestamptz,
    created_at  timestamptz        NOT NULL DEFAULT now()
);

-- Issuing a new token invalidates the previous one, so only one link per
-- purpose can ever be live. The service deletes the old row first; this index
-- is the guarantee that it did.
CREATE UNIQUE INDEX user_tokens_one_live_per_purpose
    ON user_tokens (user_id, purpose)
    WHERE consumed_at IS NULL;

CREATE INDEX user_tokens_user_id ON user_tokens (user_id);

-- ------------------------------------------------------------------ sessions

-- A signed-in browser. Separate from api_keys on purpose: different subject
-- (a person, not a service), different lifetime, different revocation story.
CREATE TABLE sessions (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash   bytea       NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),

    -- Context for a "your active sessions" screen and for revoking one device.
    user_agent   text,
    ip           inet,

    expires_at   timestamptz NOT NULL,
    revoked_at   timestamptz,
    last_seen_at timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX sessions_user_id ON sessions (user_id);

-- Sweeping expired sessions: cheap because it is exactly this index's order.
CREATE INDEX sessions_expires_at ON sessions (expires_at);
