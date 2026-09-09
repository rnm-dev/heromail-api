-- Domain removal must not turn retained outbound correspondence into shared mail.
ALTER TABLE emails ADD COLUMN retained_owner_id uuid REFERENCES users(id);
CREATE FUNCTION retain_mailbox_privacy() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.owner_user_id IS NOT NULL THEN
  UPDATE emails SET retained_owner_id=OLD.owner_user_id
  WHERE workspace_id=coalesce(OLD.personal_workspace_id,(SELECT workspace_id FROM domains WHERE id=OLD.domain_id))
  AND lower(from_addr)=lower(OLD.local_part || '@' || (SELECT domain FROM domains WHERE id=OLD.domain_id));
 END IF;
 RETURN OLD;
END $$;
-- Capture before the domain disappears (its mailbox cascade runs afterwards).
CREATE FUNCTION retain_domain_mail_privacy() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 UPDATE emails e SET retained_owner_id=m.owner_user_id FROM mailboxes m
 WHERE m.domain_id=OLD.id AND m.owner_user_id IS NOT NULL
 AND e.workspace_id=coalesce(m.personal_workspace_id,OLD.workspace_id)
 AND lower(e.from_addr)=lower(m.local_part || '@' || OLD.domain);
 RETURN OLD;
END $$;
CREATE TRIGGER retain_mailbox_privacy BEFORE DELETE ON mailboxes FOR EACH ROW EXECUTE FUNCTION retain_mailbox_privacy();
CREATE TRIGGER retain_domain_mail_privacy BEFORE DELETE ON domains FOR EACH ROW EXECUTE FUNCTION retain_domain_mail_privacy();
