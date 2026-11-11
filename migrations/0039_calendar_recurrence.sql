-- Repeating events: an RRULE subset (see internal/calendar/recur.go), skipped
-- occurrence dates in the event's zone, and when the last occurrence ends
-- (NULL for an endless series) so range queries can skip finished series.
ALTER TABLE calendar_events
  ADD COLUMN rrule text NOT NULL DEFAULT '',
  ADD COLUMN exdates text[] NOT NULL DEFAULT '{}',
  ADD COLUMN series_until timestamptz;
