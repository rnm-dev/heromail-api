INSERT INTO imap_folders(mailbox_id,name) SELECT id,'Junk' FROM mailboxes ON CONFLICT DO NOTHING;
CREATE OR REPLACE FUNCTION create_imap_inbox() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO imap_folders(mailbox_id,name) VALUES(NEW.id,'INBOX'),(NEW.id,'Junk');
 RETURN NEW;
END $$;
