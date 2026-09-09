-- NULL remains an explicitly shared mailbox; existing shared access is preserved.
ALTER TABLE mailboxes ADD COLUMN owner_user_id uuid REFERENCES users(id);
CREATE INDEX mailboxes_owner_user ON mailboxes(owner_user_id) WHERE owner_user_id IS NOT NULL;
