-- Add response revisions and recoverable dispatcher claims. Separate from
-- 0020 so databases that picked up the calendar schema during dev converge.
ALTER TABLE calendar_attendees ADD COLUMN response_version integer NOT NULL DEFAULT 0;
ALTER TABLE calendar_jobs
  ADD COLUMN actor text NOT NULL DEFAULT '',
  ADD COLUMN response text NOT NULL DEFAULT '',
  ADD COLUMN response_version integer NOT NULL DEFAULT 0,
  ADD COLUMN claimed_at timestamptz;
ALTER TABLE calendar_jobs DROP CONSTRAINT calendar_jobs_event_id_event_version_kind_recipient_key;
CREATE UNIQUE INDEX calendar_jobs_revision_unique ON calendar_jobs(event_id,event_version,kind,recipient,actor,response_version);
ALTER TABLE emails
  ADD COLUMN calendar_ics text NOT NULL DEFAULT '',
  ADD COLUMN calendar_method text NOT NULL DEFAULT '' CHECK (calendar_method IN ('','REQUEST','CANCEL','REPLY'));
