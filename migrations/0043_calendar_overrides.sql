-- Changed single occurrences of a repeating event (iCalendar RECURRENCE-ID
-- instances): a JSON array of {occurrence, title, location, description,
-- start, end, start_at, end_at}, keyed by the occurrence's original date.
ALTER TABLE calendar_events ADD COLUMN overrides jsonb NOT NULL DEFAULT '[]';
ALTER TABLE calendar_external_events ADD COLUMN overrides jsonb NOT NULL DEFAULT '[]';
