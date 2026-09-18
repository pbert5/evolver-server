-- Normalized, append-only central history for controller-originated facts.
-- The JSON controller projection remains a compatibility/read-model surface;
-- these relations are the durable query surface and are never rewritten.
CREATE TABLE IF NOT EXISTS evolver.controller_event_history (
    controller_id text NOT NULL,
    controller_generation integer NOT NULL CHECK (controller_generation > 0),
    run_id text NOT NULL,
    sequence integer NOT NULL CHECK (sequence > 0),
    event_id text,
    event_type text NOT NULL,
    occurred_at timestamptz,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    payload_digest text NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
    recorded_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (controller_id, controller_generation, run_id, sequence)
);
CREATE UNIQUE INDEX IF NOT EXISTS evolver_controller_event_history_event_id_idx
    ON evolver.controller_event_history (controller_id, event_id)
    WHERE event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS evolver_controller_event_history_query_idx
    ON evolver.controller_event_history (controller_id, run_id, sequence);

CREATE TABLE IF NOT EXISTS evolver.controller_telemetry_history (
    controller_id text NOT NULL,
    controller_generation integer NOT NULL CHECK (controller_generation > 0),
    stream_id text NOT NULL,
    sequence integer NOT NULL CHECK (sequence > 0),
    instrument_id text,
    vial_position_id text,
    captured_at timestamptz,
    metric text,
    value double precision,
    unit text,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    payload_digest text NOT NULL CHECK (payload_digest ~ '^[0-9a-f]{64}$'),
    recorded_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (controller_id, controller_generation, stream_id, sequence)
);
CREATE INDEX IF NOT EXISTS evolver_controller_telemetry_history_query_idx
    ON evolver.controller_telemetry_history (controller_id, stream_id, sequence);
CREATE INDEX IF NOT EXISTS evolver_controller_telemetry_history_metric_idx
    ON evolver.controller_telemetry_history (instrument_id, vial_position_id, metric, captured_at);

CREATE OR REPLACE FUNCTION evolver.reject_history_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
    RAISE EXCEPTION 'eVOLVER history is append-only';
END;
$$;
DROP TRIGGER IF EXISTS controller_event_history_immutable ON evolver.controller_event_history;
CREATE TRIGGER controller_event_history_immutable
    BEFORE UPDATE OR DELETE ON evolver.controller_event_history
    FOR EACH ROW EXECUTE FUNCTION evolver.reject_history_mutation();
DROP TRIGGER IF EXISTS controller_telemetry_history_immutable ON evolver.controller_telemetry_history;
CREATE TRIGGER controller_telemetry_history_immutable
    BEFORE UPDATE OR DELETE ON evolver.controller_telemetry_history
    FOR EACH ROW EXECUTE FUNCTION evolver.reject_history_mutation();

-- Scientific/run history is kept separate from the replaceable coordination
-- document.  These tables are deliberately additive so existing deployments
-- retain controller, lease, command, and calibration data.
CREATE TABLE IF NOT EXISTS evolver.experiment_bundles (
    bundle_id text PRIMARY KEY, bundle_digest text NOT NULL UNIQUE, purpose text NOT NULL,
    schema_version text NOT NULL, execution_mode text NOT NULL CHECK (execution_mode = 'declarative_state_machine'),
    definition_id text, definition_revision text, action_registry_revision text,
    source jsonb NOT NULL DEFAULT '{}'::jsonb, resolved_definition jsonb NOT NULL DEFAULT '{}'::jsonb,
    execution_plan jsonb NOT NULL DEFAULT '{}'::jsonb, accepted_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS evolver.experiment_runs (
    controller_id text NOT NULL, run_id text NOT NULL, bundle_id text, bundle_digest text, purpose text,
    state text NOT NULL, current_revision integer NOT NULL DEFAULT 0, instrument_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz, started_at timestamptz, ended_at timestamptz, last_synced_at timestamptz,
    projection jsonb NOT NULL DEFAULT '{}'::jsonb, PRIMARY KEY (controller_id, run_id)
);
CREATE INDEX IF NOT EXISTS evolver_experiment_runs_filter_idx ON evolver.experiment_runs (controller_id, purpose, state, started_at);
CREATE TABLE IF NOT EXISTS evolver.run_revisions (
    controller_id text NOT NULL, run_id text NOT NULL, revision integer NOT NULL CHECK (revision > 0),
    effective_state_digest text NOT NULL, effective_state jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (controller_id, run_id, revision)
);
CREATE TABLE IF NOT EXISTS evolver.run_events (
    controller_id text NOT NULL, run_id text NOT NULL, sequence integer NOT NULL CHECK (sequence > 0),
    event_type text NOT NULL, occurred_at timestamptz, revision integer, causation_command_id text,
    details jsonb NOT NULL DEFAULT '{}'::jsonb, content_digest text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (controller_id, run_id, sequence)
);
CREATE TABLE IF NOT EXISTS evolver.run_measurements (
    measurement_id text PRIMARY KEY, controller_id text NOT NULL, run_id text NOT NULL, instrument_id text,
    vial_position_id text, stream_id text, sequence_number integer, captured_at timestamptz,
    measurement_type text, raw_value double precision, derived_value double precision, unit text,
    source_type text, extrapolated boolean NOT NULL DEFAULT false, quality_flags jsonb NOT NULL DEFAULT '[]'::jsonb,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb, payload_digest text NOT NULL
);
CREATE INDEX IF NOT EXISTS evolver_run_measurements_query_idx ON evolver.run_measurements (controller_id, run_id, captured_at);
CREATE INDEX IF NOT EXISTS evolver_run_measurements_instrument_idx ON evolver.run_measurements (instrument_id, vial_position_id, measurement_type, captured_at);
CREATE TABLE IF NOT EXISTS evolver.run_activities (
    activity_id text PRIMARY KEY, controller_id text NOT NULL, run_id text NOT NULL, activity_type text NOT NULL,
    status text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz,
    completed_at timestamptz, payload jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS evolver_run_activities_run_idx ON evolver.run_activities (controller_id, run_id, created_at);
CREATE TABLE IF NOT EXISTS evolver.run_action_executions (
    command_id text PRIMARY KEY, controller_id text NOT NULL, run_id text NOT NULL, action_id text NOT NULL,
    step text, revision integer, operation text, status text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz, request jsonb NOT NULL DEFAULT '{}'::jsonb, result jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS evolver_run_action_executions_run_idx ON evolver.run_action_executions (controller_id, run_id, created_at);
CREATE TABLE IF NOT EXISTS evolver.run_telemetry (
    controller_id text NOT NULL, stream_id text NOT NULL, sequence integer NOT NULL CHECK (sequence > 0), run_id text,
    instrument_id text, vial_position_id text, captured_at timestamptz, payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    payload_digest text NOT NULL, PRIMARY KEY (controller_id, stream_id, sequence)
);
CREATE INDEX IF NOT EXISTS evolver_run_telemetry_time_idx ON evolver.run_telemetry (captured_at, controller_id, stream_id);
CREATE TABLE IF NOT EXISTS evolver.validation_artifacts (
    artifact_id text PRIMARY KEY, artifact_digest text NOT NULL UNIQUE, controller_id text NOT NULL, run_id text,
    bundle_id text, bundle_digest text, protocol_id text, protocol_version text, overall_result text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(), artifact jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS evolver_validation_artifacts_run_idx ON evolver.validation_artifacts (controller_id, run_id, created_at);
