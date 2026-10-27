-- New calendars start in Asia/Almaty (UTC+5); calendars left on the old UTC default move too.
ALTER TABLE calendars ALTER COLUMN timezone SET DEFAULT 'Asia/Almaty';
UPDATE calendars SET timezone='Asia/Almaty' WHERE timezone='UTC';
