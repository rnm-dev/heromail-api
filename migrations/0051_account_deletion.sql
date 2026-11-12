-- Self-service account deletion, MAL-8. See docs/accounts.md.
--
-- A deleted account is anonymised, not removed: corporate mailboxes it owned
-- keep pointing at it, which keeps their mail private (nobody else matches
-- the owner) until a workspace owner reassigns or deletes them. Every way to
-- sign in and every piece of personal data is deleted; what remains is the id,
-- a placeholder address and this timestamp.
ALTER TABLE users ADD COLUMN deleted_at timestamptz;
