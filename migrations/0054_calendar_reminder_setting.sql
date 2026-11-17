-- Separate switch for meeting reminder pushes (MAL-39); on by default.
-- See docs/mobile-api.md.
ALTER TABLE notification_settings ADD COLUMN calendar_reminders boolean NOT NULL DEFAULT true;
