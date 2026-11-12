-- A member lets a colleague in the same workspace see their calendar (titles
-- and times, read-only). Removing either membership removes the share.
CREATE TABLE calendar_shares (
  calendar_id uuid NOT NULL REFERENCES calendars(id) ON DELETE CASCADE,
  workspace_id uuid NOT NULL,
  grantee_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (calendar_id, grantee_id),
  FOREIGN KEY (workspace_id, grantee_id) REFERENCES workspace_members(workspace_id, user_id) ON DELETE CASCADE
);
CREATE INDEX calendar_shares_grantee ON calendar_shares(workspace_id, grantee_id);
