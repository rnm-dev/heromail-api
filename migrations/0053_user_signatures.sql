-- Gmail-style signatures: a user's named HTML signatures plus, per sending
-- address, which one is inserted into new mail and into replies/forwards.
-- See docs/composer-formatting-signatures.md.
CREATE TABLE user_signatures (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 name text NOT NULL,
 html text NOT NULL DEFAULT '',
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX user_signatures_user ON user_signatures(user_id, created_at);

CREATE TABLE signature_defaults (
 workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 sender text NOT NULL,
 new_signature_id uuid REFERENCES user_signatures(id) ON DELETE SET NULL,
 reply_signature_id uuid REFERENCES user_signatures(id) ON DELETE SET NULL,
 PRIMARY KEY (workspace_id, user_id, sender)
);

-- Carry over the old per-sender plain-text signatures: each becomes a named
-- signature (escaped to HTML) and the default for new mail and replies.
WITH carried AS MATERIALIZED (
 SELECT gen_random_uuid() AS id, workspace_id, user_id, sender, text_body FROM mail_signatures WHERE btrim(text_body) <> ''
), created AS (
 INSERT INTO user_signatures(id,user_id,name,html)
 SELECT id, user_id, sender,
  replace(replace(replace(replace(replace(text_body,'&','&amp;'),'<','&lt;'),'>','&gt;'),E'\r\n',E'\n'),E'\n','<br>')
 FROM carried RETURNING id
)
INSERT INTO signature_defaults(workspace_id,user_id,sender,new_signature_id,reply_signature_id)
SELECT c.workspace_id, c.user_id, c.sender, c.id, c.id FROM carried c JOIN created USING (id);
