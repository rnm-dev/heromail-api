-- Meeting rooms of a workspace and the room an event books. A room can hold
-- one meeting at a time; Save rejects overlapping bookings.
CREATE TABLE calendar_rooms (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  name text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 100),
  capacity integer NOT NULL DEFAULT 0 CHECK (capacity BETWEEN 0 AND 10000),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX calendar_rooms_name ON calendar_rooms(workspace_id, lower(name));
ALTER TABLE calendar_events ADD COLUMN room_id uuid REFERENCES calendar_rooms(id) ON DELETE SET NULL;
CREATE INDEX calendar_events_room ON calendar_events(room_id) WHERE room_id IS NOT NULL;
