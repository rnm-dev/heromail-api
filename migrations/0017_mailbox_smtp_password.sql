-- Independent, send-only application credentials; never an account/IMAP password.
CREATE TABLE mailbox_smtp_credentials (
 mailbox_id uuid PRIMARY KEY REFERENCES mailboxes(id) ON DELETE CASCADE,
 password_hash text NOT NULL,
 issued_by uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE FUNCTION revoke_mailbox_smtp_on_assignment() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.owner_user_id IS DISTINCT FROM NEW.owner_user_id OR OLD.personal_workspace_id IS DISTINCT FROM NEW.personal_workspace_id OR OLD.domain_id IS DISTINCT FROM NEW.domain_id THEN
  DELETE FROM mailbox_smtp_credentials WHERE mailbox_id=OLD.id;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER revoke_mailbox_smtp_assignment AFTER UPDATE ON mailboxes FOR EACH ROW EXECUTE FUNCTION revoke_mailbox_smtp_on_assignment();
CREATE FUNCTION revoke_mailbox_smtp_on_membership() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 DELETE FROM mailbox_smtp_credentials c USING mailboxes m, domains d
 WHERE c.mailbox_id=m.id AND d.id=m.domain_id AND coalesce(m.personal_workspace_id,d.workspace_id)=OLD.workspace_id AND c.issued_by=OLD.user_id;
 RETURN OLD;
END $$;
CREATE TRIGGER revoke_mailbox_smtp_membership AFTER DELETE OR UPDATE OF role,user_id,workspace_id ON workspace_members FOR EACH ROW EXECUTE FUNCTION revoke_mailbox_smtp_on_membership();
