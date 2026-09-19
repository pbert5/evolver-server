CREATE TABLE IF NOT EXISTS evolver.controller_lifecycle_events (
    event_id text PRIMARY KEY, controller_id text NOT NULL, event_type text NOT NULL, occurred_at timestamptz NOT NULL,
    actor text NOT NULL, details jsonb NOT NULL DEFAULT '{}'::jsonb
);
