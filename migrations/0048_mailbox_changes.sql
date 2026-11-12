-- Delta sync for mobile clients, MAL-5. See docs/mobile-api.md.
--
-- Every change to a mailbox's mail gets a per-mailbox, strictly increasing
-- change_seq — the role MODSEQ plays in IMAP CONDSTORE. It is recorded by
-- triggers, not by the Go code paths, so the web UI, IMAP, LMTP delivery and
-- automation rules are all covered without any of them knowing about sync.
--
-- The number is assigned at COMMIT by deferred constraint triggers, under a
-- row lock on the mailbox's counter. That makes seq order equal commit order:
-- once a reader sees counter value S, every change numbered <= S is committed
-- and visible, so a cursor can never skip a change that commits late. Taking
-- the counter lock last (at commit, after every row lock the transaction
-- needs) is also what keeps it from deadlocking against row locks.
--
-- -1 marks a row changed in this transaction but not yet numbered.

CREATE TABLE mailbox_sync (
    mailbox_id       uuid   PRIMARY KEY REFERENCES mailboxes (id) ON DELETE CASCADE,
    -- The latest change_seq handed out in this mailbox.
    seq              bigint NOT NULL DEFAULT 0,
    -- The seq of the latest folder or label definition change.
    organization_seq bigint NOT NULL DEFAULT 0,
    -- Cursors below this are 410 cursor_expired: tombstones they would need
    -- have been pruned.
    min_seq          bigint NOT NULL DEFAULT 0
);
INSERT INTO mailbox_sync (mailbox_id) SELECT id FROM mailboxes;

-- Existing mail is change 0: a client starts from a full listing anyway.
ALTER TABLE messages ADD COLUMN change_seq bigint NOT NULL DEFAULT 0;
CREATE INDEX messages_mailbox_change_seq ON messages (mailbox_id, change_seq);

-- Deleted messages, so a client can drop them from its cache. Not FK'd to
-- mailboxes: they are written while a mailbox's own cascade is running.
CREATE TABLE message_tombstones (
    mailbox_id uuid        NOT NULL,
    message_id uuid        NOT NULL,
    change_seq bigint      NOT NULL DEFAULT -1,
    deleted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (mailbox_id, message_id)
);
CREATE INDEX message_tombstones_change_seq ON message_tombstones (mailbox_id, change_seq);
CREATE INDEX message_tombstones_deleted_at ON message_tombstones (deleted_at);

-- Next number for a mailbox, or NULL when the mailbox no longer exists.
CREATE FUNCTION mail_sync_next(box uuid) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE s bigint;
BEGIN
    INSERT INTO mailbox_sync AS m (mailbox_id, seq)
    SELECT box, 1 WHERE EXISTS (SELECT 1 FROM mailboxes WHERE id = box)
    ON CONFLICT (mailbox_id) DO UPDATE SET seq = m.seq + 1
    RETURNING m.seq INTO s;
    RETURN s;
END;
$$;

-- What a list card shows. Anything else (bodies, raw) is immutable after
-- delivery, and imap_uid follows folder.
CREATE FUNCTION messages_sync_mark() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT'
       OR NEW.folder IS DISTINCT FROM OLD.folder
       OR NEW.imap_flags IS DISTINCT FROM OLD.imap_flags
       OR NEW.read_at IS DISTINCT FROM OLD.read_at
       OR NEW.category IS DISTINCT FROM OLD.category
       OR NEW.subject IS DISTINCT FROM OLD.subject THEN
        NEW.change_seq := -1;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER messages_sync_mark BEFORE INSERT OR UPDATE ON messages
    FOR EACH ROW EXECUTE FUNCTION messages_sync_mark();

CREATE FUNCTION messages_sync_assign() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE s bigint;
BEGIN
    -- One event per write; the first one numbers the row, the rest find it
    -- already numbered (or deleted) and stop.
    PERFORM 1 FROM messages WHERE id = NEW.id AND change_seq = -1;
    IF NOT FOUND THEN RETURN NULL; END IF;
    s := mail_sync_next(NEW.mailbox_id);
    IF s IS NOT NULL THEN
        UPDATE messages SET change_seq = s WHERE id = NEW.id;
    END IF;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER messages_sync_assign AFTER INSERT OR UPDATE ON messages
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW WHEN (NEW.change_seq = -1) EXECUTE FUNCTION messages_sync_assign();

-- Labels are part of the card: adding or removing one is a message change.
CREATE FUNCTION message_labels_sync_mark() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE msg uuid;
BEGIN
    IF TG_OP = 'DELETE' THEN msg := OLD.message_id; ELSE msg := NEW.message_id; END IF;
    UPDATE messages SET change_seq = -1 WHERE id = msg AND change_seq <> -1;
    RETURN NULL;
END;
$$;
CREATE TRIGGER message_labels_sync_mark AFTER INSERT OR DELETE ON message_labels
    FOR EACH ROW EXECUTE FUNCTION message_labels_sync_mark();

CREATE FUNCTION messages_sync_tombstone() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO message_tombstones (mailbox_id, message_id) VALUES (OLD.mailbox_id, OLD.id)
    ON CONFLICT (mailbox_id, message_id) DO UPDATE SET change_seq = -1, deleted_at = now();
    RETURN NULL;
END;
$$;
CREATE TRIGGER messages_sync_tombstone AFTER DELETE ON messages
    FOR EACH ROW EXECUTE FUNCTION messages_sync_tombstone();

CREATE FUNCTION message_tombstones_assign() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE s bigint;
BEGIN
    PERFORM 1 FROM message_tombstones
    WHERE mailbox_id = NEW.mailbox_id AND message_id = NEW.message_id AND change_seq = -1;
    IF NOT FOUND THEN RETURN NULL; END IF;
    s := mail_sync_next(NEW.mailbox_id);
    IF s IS NULL THEN
        -- The whole mailbox went; nobody can sync it any more.
        DELETE FROM message_tombstones WHERE mailbox_id = NEW.mailbox_id;
    ELSE
        UPDATE message_tombstones SET change_seq = s
        WHERE mailbox_id = NEW.mailbox_id AND message_id = NEW.message_id;
    END IF;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER message_tombstones_assign AFTER INSERT OR UPDATE ON message_tombstones
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW WHEN (NEW.change_seq = -1) EXECUTE FUNCTION message_tombstones_assign();

-- Folder and label definitions: one counter bump per change, and the client
-- refetches /organization when organization_seq passes its cursor.
CREATE FUNCTION mail_organization_sync() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE box uuid; s bigint;
BEGIN
    IF TG_OP = 'DELETE' THEN box := OLD.mailbox_id; ELSE box := NEW.mailbox_id; END IF;
    s := mail_sync_next(box);
    IF s IS NOT NULL THEN
        UPDATE mailbox_sync SET organization_seq = s WHERE mailbox_id = box;
    END IF;
    RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER imap_folders_sync AFTER INSERT OR UPDATE OR DELETE ON imap_folders
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION mail_organization_sync();
CREATE CONSTRAINT TRIGGER mail_labels_sync AFTER INSERT OR UPDATE OR DELETE ON mail_labels
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION mail_organization_sync();
