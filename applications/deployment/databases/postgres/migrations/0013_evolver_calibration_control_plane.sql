CREATE TABLE IF NOT EXISTS evolver.calibration_artifacts (
    artifact_id text PRIMARY KEY, artifact_digest text NOT NULL UNIQUE, instrument_id text NOT NULL, vial_position_id text,
    calibration_type text NOT NULL, created_at timestamptz NOT NULL, performed_at timestamptz NOT NULL, performed_by text NOT NULL, artifact jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS evolver.calibration_events (
    event_id text PRIMARY KEY, artifact_id text NOT NULL REFERENCES evolver.calibration_artifacts(artifact_id), event_type text NOT NULL,
    occurred_at timestamptz NOT NULL, actor text, reason text, details jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE TABLE IF NOT EXISTS evolver.calibration_distribution_facts (
    event_id text PRIMARY KEY REFERENCES evolver.calibration_events(event_id), artifact_id text NOT NULL REFERENCES evolver.calibration_artifacts(artifact_id),
    command_id text NOT NULL, controller_id text NOT NULL, controller_generation integer NOT NULL CHECK (controller_generation > 0),
    artifact_digest text NOT NULL, state text NOT NULL CHECK (state IN ('requested','stored','failed')), request_id text
);
