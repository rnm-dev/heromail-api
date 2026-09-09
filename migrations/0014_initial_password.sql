ALTER TABLE users ADD COLUMN must_change_password boolean NOT NULL DEFAULT false;
COMMENT ON COLUMN users.must_change_password IS 'Set true when provisioning an account with an administrator-issued initial password';
