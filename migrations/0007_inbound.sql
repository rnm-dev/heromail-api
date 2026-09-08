-- Inbound mail: the addresses we accept for, and what arrives at them.
--
-- This is the first half of receiving. Postfix accepts a message on :25 and
-- hands it to the backend over LMTP; everything below is what the backend does
-- with it.

-- ---------------------------------------------------------------- mailboxes

-- One row per address we will accept mail for. Scoped to a domain rather than
-- a workspace directly: the domain is what proves ownership, and it already
-- carries the workspace. Deriving the tenant from the address means a mailbox
-- can never disagree with the domain it lives under.
CREATE TABLE mailboxes (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    domain_id  uuid        NOT NULL REFERENCES domains (id) ON DELETE CASCADE,

    -- The part before the @. Stored separately from the domain so renaming a
    -- domain does not mean rewriting every address under it, and compared
    -- case-insensitively because nobody expects Sales@ and sales@ to differ.
    local_part citext      NOT NULL CHECK (btrim(local_part) <> ''),

    -- Optional human label for the UI ("Sales", "Support").
    name       text,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    UNIQUE (domain_id, local_part)
);

CREATE TRIGGER mailboxes_set_updated_at
    BEFORE UPDATE ON mailboxes
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ----------------------------------------------------------------- messages

CREATE TABLE messages (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    mailbox_id  uuid        NOT NULL REFERENCES mailboxes (id) ON DELETE CASCADE,

    -- The envelope, as the sending server stated it. Kept apart from the
    -- headers below because they can disagree, and when they do the envelope
    -- is the truth about who actually sent this and where it was going.
    envelope_from text      NOT NULL DEFAULT '',
    envelope_to   text      NOT NULL,

    -- Parsed from the headers, for the message list. Nullable because a
    -- malformed message still has to be storable — refusing to keep mail we
    -- accepted would lose it.
    message_id  text,
    from_addr   text,
    from_name   text,
    subject     text        NOT NULL DEFAULT '',
    sent_at     timestamptz,

    text_body   text,
    html_body   text,

    -- The message exactly as received, before any parsing. Everything above is
    -- derived from it, so a parser bug is recoverable: reparse rather than
    -- re-receive, which is impossible.
    --
    -- In Postgres for now, deliberately. Object storage is where this belongs
    -- (see docs/mail-infrastructure.md) but no bucket is configured yet, and a
    -- receiver that cannot store is worse than one storing in the wrong place.
    -- The LMTP listener caps message size so this cannot grow without bound.
    raw         bytea       NOT NULL,
    size_bytes  int         NOT NULL CHECK (size_bytes > 0),

    -- Authentication results as our own MTA saw them, for a "this really is
    -- from your bank" badge and for spam triage later.
    spf_pass    boolean,
    dkim_pass   boolean,

    read_at     timestamptz,
    received_at timestamptz NOT NULL DEFAULT now()
);

-- The mailbox view: newest first.
CREATE INDEX messages_mailbox_received_at ON messages (mailbox_id, received_at DESC);

-- Deduplication. A sending server that retries after a timeout delivers the
-- same message twice; the Message-ID identifies it. Partial, because a message
-- without one is still deliverable and must not collide with every other
-- message that also lacks one.
CREATE UNIQUE INDEX messages_mailbox_message_id
    ON messages (mailbox_id, message_id)
    WHERE message_id IS NOT NULL;

-- Backs the unread badge.
CREATE INDEX messages_unread ON messages (mailbox_id) WHERE read_at IS NULL;
