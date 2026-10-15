CREATE TABLE mail_signatures (
 workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 sender text NOT NULL,
 text_body text NOT NULL,
 version integer NOT NULL DEFAULT 1,
 PRIMARY KEY (workspace_id, user_id, sender)
);
