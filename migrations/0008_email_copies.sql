-- Keep envelope-only Bcc separate from recipients exposed in MIME headers.
ALTER TABLE emails ADD COLUMN cc_addrs text[] NOT NULL DEFAULT '{}';
ALTER TABLE emails ADD COLUMN bcc_addrs text[] NOT NULL DEFAULT '{}';
