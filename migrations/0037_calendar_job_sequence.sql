-- The SEQUENCE an invitation job carries, so an edit that does not change the
-- meeting (reminder, added attendee) re-sends only to those who lack it.
ALTER TABLE calendar_jobs ADD COLUMN sequence integer NOT NULL DEFAULT 0;
