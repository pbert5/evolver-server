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
