-- Wake the push dispatcher (cmd/worker) whenever a mailbox changes, MAL-3.
-- NOTIFY is delivered at commit and de-duplicated within a transaction, so a
-- bulk update of a thousand messages is one notification per mailbox.
CREATE OR REPLACE FUNCTION mail_sync_next(box uuid) RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE s bigint;
BEGIN
    INSERT INTO mailbox_sync AS m (mailbox_id, seq)
    SELECT box, 1 WHERE EXISTS (SELECT 1 FROM mailboxes WHERE id = box)
    ON CONFLICT (mailbox_id) DO UPDATE SET seq = m.seq + 1
    RETURNING m.seq INTO s;
    IF s IS NOT NULL THEN
        PERFORM pg_notify('mailbox_changes', box::text);
    END IF;
    RETURN s;
END;
$$;
