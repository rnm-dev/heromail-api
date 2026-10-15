CREATE TABLE contacts (
 id uuid PRIMARY KEY,
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 name text NOT NULL,
 email text NOT NULL,
 version integer NOT NULL DEFAULT 1 CHECK(version > 0),
 UNIQUE(user_id,email)
);
CREATE INDEX contacts_user_name ON contacts(user_id,lower(name),email,id);
