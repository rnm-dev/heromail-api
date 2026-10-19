-- Smart inbox: every received message is sorted into people, notifications or
-- newsletters. Existing rows start as people and are reclassified by
-- cmd/categorize; category_reason='' marks a row never classified.
ALTER TABLE messages
 ADD category text NOT NULL DEFAULT 'people' CHECK (category IN ('people','notifications','newsletters')),
 ADD category_reason text NOT NULL DEFAULT '';
CREATE INDEX messages_category ON messages(mailbox_id, folder, category, received_at DESC);
-- A user's correction for one sender wins over every automatic signal.
CREATE TABLE sender_categories (
 mailbox_id uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
 sender text NOT NULL CHECK (sender = lower(sender) AND sender <> ''),
 category text NOT NULL CHECK (category IN ('people','notifications','newsletters')),
 updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (mailbox_id, sender)
);
-- Sender history lookups during delivery.
CREATE INDEX emails_from_addr ON emails(from_addr);
