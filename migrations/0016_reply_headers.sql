ALTER TABLE emails ADD COLUMN in_reply_to text NOT NULL DEFAULT '';
ALTER TABLE emails ADD COLUMN reply_references text NOT NULL DEFAULT '';
