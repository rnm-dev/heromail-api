-- Accepted external invitations may repeat, like Heromail's own events.
ALTER TABLE calendar_external_events
  ADD COLUMN rrule text NOT NULL DEFAULT '',
  ADD COLUMN exdates text[] NOT NULL DEFAULT '{}',
  ADD COLUMN series_until timestamptz;
