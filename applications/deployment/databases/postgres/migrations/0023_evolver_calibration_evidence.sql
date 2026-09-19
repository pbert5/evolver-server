CREATE TABLE IF NOT EXISTS evolver.od_blank_evidence (
    record_id text NOT NULL, controller_id text NOT NULL, controller_generation integer NOT NULL CHECK (controller_generation > 0), instrument_id text NOT NULL,
    blank_id text NOT NULL, channel_index integer NOT NULL CHECK (channel_index BETWEEN 0 AND 5), raw_adc double precision NOT NULL, captured_at timestamptz NOT NULL,
    evidence jsonb NOT NULL DEFAULT '{}'::jsonb, PRIMARY KEY (controller_id, controller_generation, record_id)
);
