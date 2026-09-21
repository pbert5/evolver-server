-- #136 blocker repair: aggregate fencing and lossless compatibility envelopes.
ALTER TABLE evolver.controller_projections ADD COLUMN IF NOT EXISTS revision bigint NOT NULL DEFAULT 0;
ALTER TABLE evolver.calibration_events ADD COLUMN IF NOT EXISTS payload jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE evolver.run_resource_assignments ADD COLUMN IF NOT EXISTS payload jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE evolver.run_resource_events ADD COLUMN IF NOT EXISTS payload jsonb NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE evolver.od_blank_evidence ADD COLUMN IF NOT EXISTS payload jsonb NOT NULL DEFAULT '{}'::jsonb;
INSERT INTO system.schema_versions (component, version, description)
VALUES ('meta_webui_interface.database', '0029_evolver_persistence_conflicts', 'Aggregate fencing and lossless persistence envelopes')
ON CONFLICT (component, version) DO NOTHING;
