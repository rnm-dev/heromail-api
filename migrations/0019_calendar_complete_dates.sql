-- SQL CHECK accepts NULL; explicitly require both interval endpoints.
ALTER TABLE calendar_events ADD CONSTRAINT calendar_event_complete_interval
CHECK ((all_day AND start_date IS NOT NULL AND end_date IS NOT NULL)
 OR (NOT all_day AND start_at IS NOT NULL AND end_at IS NOT NULL));
