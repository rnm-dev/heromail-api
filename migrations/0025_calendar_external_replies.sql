-- Answers to invitations from external organizers. The REPLY is ordinary
-- outbound mail; this row remembers the latest choice per message. The row is
-- written before sending so a retry reuses the same DTSTAMP and idempotency key;
-- email_id stays NULL until the REPLY is queued.
CREATE TABLE calendar_external_replies (
  message_id uuid PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
  attendee text NOT NULL,
  response text NOT NULL CHECK (response IN ('accepted','tentative','declined')),
  revision integer NOT NULL CHECK (revision > 0),
  stamp timestamptz NOT NULL,
  email_id uuid,
  updated_at timestamptz NOT NULL DEFAULT now()
);
