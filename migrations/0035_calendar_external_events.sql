-- Invitations from external organizers that a user accepted (or tentatively
-- accepted) from a received message. They are private read-only copies in the
-- answering user's calendar, keyed by the organizer's UID; a later answer or
-- a newer SEQUENCE replaces the copy, "declined" removes it.
CREATE TABLE calendar_external_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  calendar_id uuid NOT NULL REFERENCES calendars(id) ON DELETE CASCADE,
  uid text NOT NULL,
  sequence integer NOT NULL DEFAULT 0,
  message_id uuid REFERENCES messages(id) ON DELETE SET NULL,
  attendee text NOT NULL,
  response text NOT NULL CHECK (response IN ('accepted','tentative')),
  organizer_email text NOT NULL,
  title text NOT NULL,
  description text NOT NULL DEFAULT '',
  location text NOT NULL DEFAULT '',
  timezone text NOT NULL,
  all_day boolean NOT NULL,
  start_at timestamptz,
  end_at timestamptz,
  start_date date,
  end_date date,
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(calendar_id,uid),
  CHECK ((all_day AND start_at IS NULL AND end_at IS NULL AND start_date IS NOT NULL AND end_date>start_date)
    OR (NOT all_day AND start_date IS NULL AND end_date IS NULL AND start_at IS NOT NULL AND end_at>start_at))
);
