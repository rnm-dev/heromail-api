CREATE TABLE mailbox_automation (
 mailbox_id uuid PRIMARY KEY REFERENCES mailboxes(id) ON DELETE CASCADE,
 version integer NOT NULL CHECK(version>0),
 config jsonb NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE vacation_recipients (
 mailbox_id uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
 recipient text NOT NULL,
 reserved_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(mailbox_id,recipient)
);
CREATE TABLE vacation_jobs (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 mailbox_id uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
 message_id uuid NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
 config_version integer NOT NULL,
 recipient text NOT NULL,
 subject text NOT NULL,
 body text NOT NULL,
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','queued','skipped','dead')),
 attempts integer NOT NULL DEFAULT 0,
 due_at timestamptz NOT NULL DEFAULT now(),
 created_at timestamptz NOT NULL DEFAULT now(),
 last_error text,
 email_id uuid REFERENCES emails(id) ON DELETE SET NULL,
 UNIQUE(message_id)
);
CREATE INDEX vacation_jobs_due ON vacation_jobs(due_at) WHERE status='pending';
CREATE INDEX vacation_jobs_mailbox_created ON vacation_jobs(mailbox_id,created_at);
ALTER TABLE emails ADD COLUMN auto_reply boolean NOT NULL DEFAULT false;
