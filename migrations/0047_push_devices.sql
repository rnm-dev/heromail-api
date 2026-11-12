-- Push registrations (FCM registration tokens) for mobile sessions, MAL-2.
-- See docs/mobile-api.md.

CREATE TYPE push_platform AS ENUM ('ios', 'android');
-- Only FCM today (iOS goes through Firebase too); the enum leaves room for a
-- direct APNs or web-push provider without a table change.
CREATE TYPE push_provider AS ENUM ('fcm');

-- Lets push_devices reference (session, user) as a pair, so a row can never
-- name a user other than the session's own.
ALTER TABLE sessions ADD CONSTRAINT sessions_id_user_id_key UNIQUE (id, user_id);

CREATE TABLE push_devices (
    id           uuid          PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid          NOT NULL,
    -- One registration per session: a session is one app install.
    session_id   uuid          NOT NULL UNIQUE,
    platform     push_platform NOT NULL,
    provider     push_provider NOT NULL DEFAULT 'fcm',
    -- One token belongs to exactly one session. Registering it from another
    -- session (another user signing in on the same phone) moves it.
    token        text          NOT NULL UNIQUE CHECK (char_length(token) BETWEEN 1 AND 4096),
    locale       text          CHECK (char_length(locale) <= 35),
    timezone     text          CHECK (char_length(timezone) <= 64),
    app_version  text          CHECK (char_length(app_version) <= 50),
    created_at   timestamptz   NOT NULL DEFAULT now(),
    last_seen_at timestamptz   NOT NULL DEFAULT now(),
    -- Set when FCM answers UNREGISTERED; the sender skips the row, and a fresh
    -- registration of the same token clears it.
    disabled_at  timestamptz,
    FOREIGN KEY (session_id, user_id) REFERENCES sessions (id, user_id) ON DELETE CASCADE
);

-- The sender's lookup: a user's deliverable devices.
CREATE INDEX push_devices_user_active ON push_devices (user_id) WHERE disabled_at IS NULL;

-- Sessions are revoked by UPDATE, not DELETE, so the cascade alone would leave
-- a signed-out phone receiving mail notifications. Doing it in a trigger covers
-- every revocation path at once: logout, DELETE /auth/sessions/{id}, refresh
-- reuse detection, password change and reset.
CREATE FUNCTION push_devices_drop_on_revoke() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM push_devices WHERE session_id = NEW.id;
    RETURN NEW;
END;
$$;

CREATE TRIGGER sessions_revoke_drops_push
    AFTER UPDATE OF revoked_at ON sessions
    FOR EACH ROW
    WHEN (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL)
    EXECUTE FUNCTION push_devices_drop_on_revoke();
