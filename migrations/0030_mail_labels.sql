CREATE TABLE mail_labels (
 id uuid PRIMARY KEY,
 mailbox_id uuid NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
 name text NOT NULL,
 version integer NOT NULL DEFAULT 1 CHECK(version>0),
 UNIQUE(mailbox_id,name), UNIQUE(mailbox_id,id)
);
ALTER TABLE messages ADD UNIQUE(mailbox_id,id);
CREATE TABLE message_labels (
 mailbox_id uuid NOT NULL,
 message_id uuid NOT NULL,
 label_id uuid NOT NULL,
 PRIMARY KEY(message_id,label_id),
 FOREIGN KEY(mailbox_id,message_id) REFERENCES messages(mailbox_id,id) ON DELETE CASCADE,
 FOREIGN KEY(mailbox_id,label_id) REFERENCES mail_labels(mailbox_id,id) ON DELETE CASCADE
);
CREATE INDEX message_labels_label ON message_labels(label_id,message_id);
