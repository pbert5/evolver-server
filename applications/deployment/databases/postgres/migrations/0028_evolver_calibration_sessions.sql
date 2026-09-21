CREATE TABLE IF NOT EXISTS evolver.calibration_sessions (
    session_id text PRIMARY KEY,
    instrument_id text NOT NULL,
    calibration_type text NOT NULL,
    created_at timestamptz NOT NULL,
    session jsonb NOT NULL
);

CREATE INDEX IF NOT EXISTS evolver_calibration_sessions_instrument_idx
    ON evolver.calibration_sessions (instrument_id, created_at DESC);

INSERT INTO system.schema_versions (component, version, description)
VALUES ('meta_webui_interface.database', '0028_evolver_calibration_sessions', 'Normalized calibration session durability')
ON CONFLICT (component, version) DO NOTHING;
