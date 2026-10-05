-- Personal calendar is scoped to the membership, not to mailbox ownership.
CREATE TABLE calendars (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 workspace_id uuid NOT NULL,
 user_id uuid NOT NULL,
 timezone text NOT NULL DEFAULT 'UTC',
 UNIQUE(workspace_id,user_id),
 FOREIGN KEY(workspace_id,user_id) REFERENCES workspace_members(workspace_id,user_id) ON DELETE CASCADE
);
CREATE TABLE calendar_events (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 calendar_id uuid NOT NULL REFERENCES calendars(id) ON DELETE CASCADE,
 title text NOT NULL CHECK(length(btrim(title)) BETWEEN 1 AND 200),
 description text NOT NULL DEFAULT '',
 location text NOT NULL DEFAULT '',
 timezone text NOT NULL,
 all_day boolean NOT NULL,
 start_at timestamptz,
 end_at timestamptz,
 start_date date,
 end_date date,
 version integer NOT NULL DEFAULT 1 CHECK(version>0),
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 CHECK ((all_day AND start_at IS NULL AND end_at IS NULL AND start_date IS NOT NULL AND end_date>start_date)
 OR (NOT all_day AND start_date IS NULL AND end_date IS NULL AND start_at IS NOT NULL AND end_at>start_at))
);
CREATE INDEX calendar_events_times ON calendar_events(calendar_id,start_at,end_at) WHERE NOT all_day;
CREATE INDEX calendar_events_dates ON calendar_events(calendar_id,start_date,end_date) WHERE all_day;
