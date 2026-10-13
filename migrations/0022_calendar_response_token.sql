-- RSVP links require a reusable opaque token so an updated invitation can
-- carry the same address-specific URL. Tokens are random UUIDs, not event IDs.
ALTER TABLE calendar_attendees DROP COLUMN IF EXISTS token_hash;
ALTER TABLE calendar_attendees ADD COLUMN response_token uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE;
