-- File attachments for outbound mail. The bytes live in an S3-compatible
-- bucket (internal/storage); this table is only the index — id, ownership,
-- and where to find the object.

CREATE TABLE attachments (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    uuid        NOT NULL REFERENCES workspaces (id) ON DELETE CASCADE,

    -- NULL until POST /v1/emails references this id. An upload that is never
    -- referenced is an orphan: nothing points at it, so there is no foreign
    -- key to model that, only an age to clean up by (see attachments_orphaned).
    email_id        uuid        REFERENCES emails (id) ON DELETE CASCADE,

    -- The name the recipient sees. Never used to build storage_key: a
    -- customer-controlled string must not become a path in our bucket.
    filename        text        NOT NULL CHECK (btrim(filename) <> ''),
    content_type    text        NOT NULL DEFAULT 'application/octet-stream',
    size_bytes      bigint      NOT NULL CHECK (size_bytes > 0),
    checksum_sha256 bytea       NOT NULL CHECK (octet_length(checksum_sha256) = 32),

    -- Object key in the bucket, generated server-side (workspace/uuid).
    storage_key     text        NOT NULL UNIQUE CHECK (btrim(storage_key) <> ''),

    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX attachments_workspace_id ON attachments (workspace_id);
CREATE INDEX attachments_email_id ON attachments (email_id);

-- What a cleanup job would scan: uploads never attached to a send, aged out.
-- No job runs yet — see docs/sending.md.
CREATE INDEX attachments_orphaned ON attachments (created_at) WHERE email_id IS NULL;
