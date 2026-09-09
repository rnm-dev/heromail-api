CREATE SEQUENCE imap_uid_seq MAXVALUE 4294967294;
CREATE SEQUENCE imap_validity_seq MAXVALUE 4294967294;
CREATE TABLE imap_folders (
 mailbox_id uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
 name text NOT NULL CHECK(length(name)>0 AND length(name)<=200),
 uidvalidity bigint NOT NULL DEFAULT nextval('imap_validity_seq'),
 subscribed boolean NOT NULL DEFAULT true,
 PRIMARY KEY(mailbox_id,name)
);
INSERT INTO imap_folders(mailbox_id,name) SELECT id,'INBOX' FROM mailboxes;
CREATE FUNCTION create_imap_inbox() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN INSERT INTO imap_folders(mailbox_id,name) VALUES(NEW.id,'INBOX'); RETURN NEW; END $$;
CREATE TRIGGER mailbox_imap_inbox AFTER INSERT ON mailboxes FOR EACH ROW EXECUTE FUNCTION create_imap_inbox();
ALTER TABLE messages ADD COLUMN imap_uid bigint;
ALTER TABLE messages ADD COLUMN folder text NOT NULL DEFAULT 'INBOX';
ALTER TABLE messages ADD COLUMN imap_flags text[] NOT NULL DEFAULT '{}';
-- Appends/copies are not SMTP retries and may retain the same Message-ID.
ALTER TABLE messages ADD COLUMN smtp_delivery boolean NOT NULL DEFAULT true;
UPDATE messages SET imap_uid=nextval('imap_uid_seq');
ALTER TABLE messages ALTER COLUMN imap_uid SET NOT NULL;
ALTER TABLE messages ADD UNIQUE(imap_uid);
ALTER TABLE messages ADD FOREIGN KEY(mailbox_id,folder) REFERENCES imap_folders(mailbox_id,name) ON DELETE CASCADE ON UPDATE CASCADE;
DROP INDEX messages_mailbox_message_id;
CREATE UNIQUE INDEX messages_mailbox_message_id ON messages(mailbox_id,message_id) WHERE message_id IS NOT NULL AND smtp_delivery;
CREATE INDEX messages_imap_folder ON messages(mailbox_id,folder,imap_uid);
CREATE FUNCTION assign_imap_uid() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 -- Serialize delivery per address before allocating a UID, so committed UIDs
 -- cannot arrive out of order on simultaneous LMTP/APPEND transactions.
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.mailbox_id::text,0));
 NEW.imap_uid := nextval('imap_uid_seq'); RETURN NEW;
END $$;
CREATE TRIGGER message_imap_uid BEFORE INSERT ON messages FOR EACH ROW EXECUTE FUNCTION assign_imap_uid();
