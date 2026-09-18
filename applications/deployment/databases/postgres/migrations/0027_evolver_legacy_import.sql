CREATE TABLE IF NOT EXISTS evolver.legacy_state_imports (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    source_digest text NOT NULL,
    source_path text NOT NULL,
    imported_at timestamptz NOT NULL DEFAULT now(),
    summary jsonb NOT NULL DEFAULT '{}'::jsonb
);
