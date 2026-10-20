-- Additional employees with access to a private mailbox. owner_user_id stays the
-- primary owner (IMAP and client SMTP sign in as that account); members read and
-- send through the web UI. Shared mailboxes (owner NULL) have no member rows.
CREATE TABLE mailbox_members (
  mailbox_id uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (mailbox_id, user_id)
);
CREATE INDEX mailbox_members_user ON mailbox_members(user_id);

-- Leaving a workspace revokes the grants it gave, not only the membership check.
CREATE FUNCTION mailbox_members_revoke() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  DELETE FROM mailbox_members mm USING mailboxes m JOIN domains d ON d.id=m.domain_id
   WHERE mm.mailbox_id=m.id AND mm.user_id=OLD.user_id
     AND coalesce(m.personal_workspace_id,d.workspace_id)=OLD.workspace_id;
  RETURN OLD;
END $$;
CREATE TRIGGER mailbox_members_revoke AFTER DELETE ON workspace_members
  FOR EACH ROW EXECUTE FUNCTION mailbox_members_revoke();
