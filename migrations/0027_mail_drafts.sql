CREATE TABLE mail_drafts (
 id uuid PRIMARY KEY,
 workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 version integer NOT NULL DEFAULT 1 CHECK(version > 0),
 data jsonb NOT NULL CHECK(jsonb_typeof(data) = 'object'),
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX mail_drafts_owner_updated ON mail_drafts(user_id, updated_at DESC, id DESC);
ALTER TABLE attachments ADD COLUMN upload_owner_id uuid REFERENCES users(id) ON DELETE CASCADE;
