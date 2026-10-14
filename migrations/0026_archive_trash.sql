INSERT INTO imap_folders(mailbox_id,name)
 SELECT id, folder FROM mailboxes CROSS JOIN (VALUES ('Archive'), ('Trash')) AS folders(folder)
 ON CONFLICT DO NOTHING;
CREATE OR REPLACE FUNCTION create_imap_inbox() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO imap_folders(mailbox_id,name)
 VALUES(NEW.id,'INBOX'),(NEW.id,'Junk'),(NEW.id,'Archive'),(NEW.id,'Trash');
 RETURN NEW;
END $$;
