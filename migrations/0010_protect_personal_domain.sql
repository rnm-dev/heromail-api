-- Deleting the service domain must not cascade into other tenants' private mail.
CREATE FUNCTION protect_personal_domain() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM mailboxes WHERE domain_id=OLD.id AND personal_workspace_id IS NOT NULL) THEN
    RAISE EXCEPTION 'domain still hosts personal mailboxes' USING ERRCODE = '23503';
  END IF;
  RETURN OLD;
END $$;
CREATE TRIGGER personal_domain_delete BEFORE DELETE ON domains
FOR EACH ROW EXECUTE FUNCTION protect_personal_domain();
