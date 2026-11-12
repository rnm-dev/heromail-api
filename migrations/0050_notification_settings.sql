-- Per-user push notification settings, MAL-4. See docs/mobile-api.md.
-- Absent rows mean defaults: the API and the sender agree on them in code
-- (push.DefaultSettings), so no row is written until a user changes something.

CREATE TABLE notification_settings (
    user_id     uuid        PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    enabled     boolean     NOT NULL DEFAULT true,
    -- Hide subject and preview; the sender is still shown.
    privacy     boolean     NOT NULL DEFAULT false,
    -- Quiet hours as local wall-clock times in timezone; start > end wraps
    -- midnight. All three set or none.
    quiet_start time,
    quiet_end   time,
    timezone    text        CHECK (char_length(timezone) <= 64),
    -- One version for the whole document, including the per-mailbox rows.
    version     integer     NOT NULL DEFAULT 0 CHECK (version >= 0),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    CHECK ((quiet_start IS NULL) = (quiet_end IS NULL) AND (quiet_start IS NULL) = (timezone IS NULL)),
    CHECK (quiet_start IS NULL OR quiet_start <> quiet_end)
);

CREATE TABLE mailbox_notification_settings (
    user_id      uuid    NOT NULL REFERENCES notification_settings (user_id) ON DELETE CASCADE,
    mailbox_id   uuid    NOT NULL REFERENCES mailboxes (id) ON DELETE CASCADE,
    enabled      boolean NOT NULL DEFAULT true,
    categories   text[]  NOT NULL DEFAULT '{people}'
                 CHECK (categories <@ ARRAY['people', 'notifications', 'newsletters']),
    -- Only messages starred on arrival (by an automation rule).
    starred_only boolean NOT NULL DEFAULT false,
    PRIMARY KEY (user_id, mailbox_id)
);
CREATE INDEX mailbox_notification_settings_mailbox ON mailbox_notification_settings (mailbox_id);
