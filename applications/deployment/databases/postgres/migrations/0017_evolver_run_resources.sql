CREATE TABLE IF NOT EXISTS evolver.run_resource_assignments (
    assignment_id text PRIMARY KEY, run_id text NOT NULL, sequence integer NOT NULL CHECK (sequence > 0), resource_kind text NOT NULL,
    resource_id text NOT NULL, assignment_state text NOT NULL, assigned_at timestamptz NOT NULL, released_at timestamptz, expires_at timestamptz NOT NULL,
    assigned_by text NOT NULL, reason text, supersedes_id text, request_id text UNIQUE, controller_generation integer, based_on_revision integer,
    sample_reference jsonb, details jsonb NOT NULL DEFAULT '{}'::jsonb, UNIQUE (run_id, sequence)
);
CREATE TABLE IF NOT EXISTS evolver.run_resource_events (
    event_id text PRIMARY KEY, run_id text NOT NULL, assignment_id text NOT NULL, event_type text NOT NULL, occurred_at timestamptz NOT NULL,
    actor text NOT NULL, reason text, details jsonb NOT NULL DEFAULT '{}'::jsonb
);
