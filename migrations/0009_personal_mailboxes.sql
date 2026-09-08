-- Personal addresses share a service domain, but never its tenant's mail access.
ALTER TABLE workspaces ADD COLUMN personal_owner_id uuid UNIQUE REFERENCES users(id);
ALTER TABLE mailboxes ADD COLUMN personal_workspace_id uuid REFERENCES workspaces(id) ON DELETE CASCADE;
CREATE UNIQUE INDEX one_personal_mailbox ON mailboxes(personal_workspace_id) WHERE personal_workspace_id IS NOT NULL;

CREATE FUNCTION protect_personal_membership() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM workspaces WHERE id = NEW.workspace_id
             AND personal_owner_id IS NOT NULL AND personal_owner_id <> NEW.user_id) THEN
    RAISE EXCEPTION 'personal workspaces cannot have other members' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER personal_membership BEFORE INSERT OR UPDATE ON workspace_members
FOR EACH ROW EXECUTE FUNCTION protect_personal_membership();
