-- Immutable eVOLVER software/firmware release identity and append-only
-- deployment facts.  A deployment event records protocol/observation facts;
-- it is not a command and never authorizes hardware actuation.
CREATE TABLE IF NOT EXISTS evolver.release_history (
    release_id text PRIMARY KEY,
    release_kind text NOT NULL CHECK (release_kind IN ('software', 'firmware')),
    version text NOT NULL,
    source_revision text NOT NULL,
    manifest_digest text NOT NULL UNIQUE,
    manifest jsonb NOT NULL,
    published_at timestamptz NOT NULL,
    published_by text NOT NULL,
    protocol_version text,
    firmware_variant text
);

CREATE TABLE IF NOT EXISTS evolver.release_deployments (
    deployment_id text PRIMARY KEY,
    release_id text NOT NULL REFERENCES evolver.release_history(release_id),
    controller_id text NOT NULL,
    controller_generation integer NOT NULL CHECK (controller_generation > 0),
    command_id text NOT NULL UNIQUE,
    requested_by text NOT NULL,
    auth_source text NOT NULL,
    requested_at timestamptz NOT NULL,
    based_on_release_id text REFERENCES evolver.release_history(release_id),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS evolver_release_deployments_controller_idx
    ON evolver.release_deployments (controller_id, requested_at DESC);

CREATE TABLE IF NOT EXISTS evolver.release_deployment_events (
    event_id text PRIMARY KEY,
    deployment_id text NOT NULL REFERENCES evolver.release_deployments(deployment_id),
    event_type text NOT NULL CHECK (event_type IN ('requested', 'command_queued', 'ack_received', 'observed', 'failed', 'rejected')),
    occurred_at timestamptz NOT NULL,
    actor text,
    controller_generation integer NOT NULL CHECK (controller_generation > 0),
    details jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS evolver_release_deployment_events_lookup_idx
    ON evolver.release_deployment_events (deployment_id, occurred_at, event_id);

CREATE FUNCTION evolver.reject_release_history_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE ignored integer; BEGIN
    RAISE EXCEPTION 'eVOLVER release history is append-only';
END;
$$;

CREATE TRIGGER evolver_release_history_immutable
BEFORE UPDATE OR DELETE ON evolver.release_history
FOR EACH ROW EXECUTE FUNCTION evolver.reject_release_history_mutation();
CREATE TRIGGER evolver_release_deployments_immutable
BEFORE UPDATE OR DELETE ON evolver.release_deployments
FOR EACH ROW EXECUTE FUNCTION evolver.reject_release_history_mutation();
CREATE TRIGGER evolver_release_deployment_events_immutable
BEFORE UPDATE OR DELETE ON evolver.release_deployment_events
FOR EACH ROW EXECUTE FUNCTION evolver.reject_release_history_mutation();

INSERT INTO system.schema_versions (component, version, description)
VALUES ('meta_webui_interface.database', '0016_evolver_release_history', 'Immutable eVOLVER release and append-only deployment history')
ON CONFLICT (component, version) DO NOTHING;
