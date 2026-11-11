-- Secret subscription URL for a personal calendar (read-only ICS feed for
-- phones and other calendar apps). NULL means the feed is off.
ALTER TABLE calendars ADD COLUMN feed_token uuid UNIQUE;
