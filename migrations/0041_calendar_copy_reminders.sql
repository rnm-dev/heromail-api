-- A participant's own reminder on a copy of someone else's meeting, and the
-- last reminder time already handled so each occurrence is reminded once.
ALTER TABLE calendar_imports ADD COLUMN reminder_minutes integer NOT NULL DEFAULT 0 CHECK (reminder_minutes IN (0,10,30,60)), ADD COLUMN reminded_until timestamptz NOT NULL DEFAULT now();
ALTER TABLE calendar_external_events ADD COLUMN reminder_minutes integer NOT NULL DEFAULT 0 CHECK (reminder_minutes IN (0,10,30,60)), ADD COLUMN reminded_until timestamptz NOT NULL DEFAULT now();
