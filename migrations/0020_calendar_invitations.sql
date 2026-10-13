-- Keep invitation identity and delivery work with the event, so edits can
-- invalidate unsent notifications without losing the audit trail.
ALTER TABLE calendar_events
  ADD COLUMN organizer_email text NOT NULL DEFAULT '',
  ADD COLUMN uid text NOT NULL DEFAULT (gen_random_uuid()::text || '@heromail.kz'),
  ADD COLUMN sequence integer NOT NULL DEFAULT 0 CHECK (sequence >= 0),
  ADD COLUMN status text NOT NULL DEFAULT 'confirmed' CHECK (status IN ('confirmed','cancelled')),
  ADD COLUMN reminder_minutes integer NOT NULL DEFAULT 0 CHECK (reminder_minutes IN (0,10,30,60));
CREATE UNIQUE INDEX calendar_events_uid ON calendar_events(uid);

CREATE TABLE calendar_attendees (
  event_id uuid NOT NULL REFERENCES calendar_events(id) ON DELETE CASCADE,
  email text NOT NULL,
  response text NOT NULL DEFAULT 'needs_action' CHECK (response IN ('needs_action','accepted','tentative','declined')),
  responded_at timestamptz,
  token_hash bytea NOT NULL UNIQUE,
  PRIMARY KEY(event_id,email)
);

CREATE TABLE calendar_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id uuid NOT NULL REFERENCES calendar_events(id) ON DELETE CASCADE,
  event_version integer NOT NULL,
  kind text NOT NULL CHECK (kind IN ('request','cancel','reminder','reply')),
  recipient text NOT NULL,
  due_at timestamptz NOT NULL DEFAULT now(),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','processing','queued','skipped','failed')),
  email_id uuid REFERENCES emails(id),
  attempts integer NOT NULL DEFAULT 0,
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(event_id,event_version,kind,recipient)
);
CREATE INDEX calendar_jobs_due ON calendar_jobs(due_at,id) WHERE status IN ('pending','failed');
