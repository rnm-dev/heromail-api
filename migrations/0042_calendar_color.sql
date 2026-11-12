-- Colour label of an own event; '' is the default accent.
ALTER TABLE calendar_events ADD COLUMN color text NOT NULL DEFAULT ''
  CHECK (color IN ('','blue','green','red','orange','purple','gray'));
