ALTER TABLE calendar_jobs DROP CONSTRAINT calendar_jobs_status_check;
ALTER TABLE calendar_jobs ADD CONSTRAINT calendar_jobs_status_check
  CHECK (status IN ('pending','processing','queued','skipped','failed','dead'));
