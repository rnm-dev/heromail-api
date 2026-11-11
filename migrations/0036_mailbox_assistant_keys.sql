-- Personal keys a mailbox owner hands to an AI assistant: IMAP and SMTP
-- submission for that one mailbox, independent of the account password.
CREATE TABLE mailbox_assistant_keys (
 mailbox_id uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 key_hash text NOT NULL,
 key_prefix text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (mailbox_id, user_id)
);
-- Reassignment or leaving the workspace revokes for good; restoring access does not revive a key.
CREATE FUNCTION revoke_assistant_keys_on_assignment() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.owner_user_id IS DISTINCT FROM NEW.owner_user_id OR OLD.personal_workspace_id IS DISTINCT FROM NEW.personal_workspace_id OR OLD.domain_id IS DISTINCT FROM NEW.domain_id THEN
  DELETE FROM mailbox_assistant_keys WHERE mailbox_id=OLD.id;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER revoke_assistant_keys_assignment AFTER UPDATE ON mailboxes FOR EACH ROW EXECUTE FUNCTION revoke_assistant_keys_on_assignment();
CREATE FUNCTION revoke_assistant_keys_on_membership() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 DELETE FROM mailbox_assistant_keys k USING mailboxes m, domains d
 WHERE k.mailbox_id=m.id AND d.id=m.domain_id AND coalesce(m.personal_workspace_id,d.workspace_id)=OLD.workspace_id AND k.user_id=OLD.user_id;
 RETURN OLD;
END $$;
CREATE TRIGGER revoke_assistant_keys_membership AFTER DELETE OR UPDATE OF user_id,workspace_id ON workspace_members FOR EACH ROW EXECUTE FUNCTION revoke_assistant_keys_on_membership();
