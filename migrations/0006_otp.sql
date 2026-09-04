-- Email verification moves from a link to a one-time code, which changes the
-- threat model: a 6-digit code has ~20 bits of entropy against a link token's
-- 256, so it is guessable unless attempts are counted and capped.
--
-- The counter lives here rather than in Redis on purpose. internal/ratelimit
-- deliberately fails open when Redis is unreachable — right for login, where
-- locking everyone out is worse than briefly not throttling, but wrong for an
-- OTP: failing open on a 6-digit code hands an attacker the whole keyspace.
-- On the row, the check is transactional with the attempt itself and survives
-- a Redis outage, a restart, and a second backend instance.

ALTER TABLE user_tokens
    -- Failed attempts against this specific code.
    ADD COLUMN attempts     int NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    -- Set once attempts hit the cap; until it passes, even a correct code is
    -- refused. NULL means "not locked".
    ADD COLUMN locked_until  timestamptz;

-- What the verification path reads: the live token for a user and purpose.
-- Unlike a link, an OTP is looked up by who is claiming it rather than by the
-- secret, because a wrong guess has to find the row in order to be counted.
CREATE INDEX user_tokens_live_lookup
    ON user_tokens (user_id, purpose)
    WHERE consumed_at IS NULL;
