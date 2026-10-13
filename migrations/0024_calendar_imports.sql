-- A recipient explicitly chooses a personal calendar for a Heromail invite.
-- The event remains owned by its organizer; imports reference the current
-- source so reschedules/cancellations cannot leave stale copies behind.
CREATE TABLE calendar_imports (
  calendar_id uuid NOT NULL REFERENCES calendars(id) ON DELETE CASCADE,
  event_id uuid NOT NULL,
  recipient text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(calendar_id,event_id),
  FOREIGN KEY(event_id,recipient) REFERENCES calendar_attendees(event_id,email) ON DELETE CASCADE
);
CREATE INDEX calendar_imports_event ON calendar_imports(event_id);
