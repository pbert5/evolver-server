-- Central eVOLVER coordination state. JSON is a compatibility bootstrap;
-- these relations are the durable, queryable runtime projection.
CREATE SCHEMA IF NOT EXISTS system;
CREATE TABLE IF NOT EXISTS system.schema_versions (
    component text NOT NULL, version text NOT NULL, description text NOT NULL DEFAULT '',
    PRIMARY KEY (component, version)
);
CREATE SCHEMA IF NOT EXISTS evolver;
CREATE TABLE IF NOT EXISTS evolver.central_state (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton), payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    revision bigint NOT NULL DEFAULT 0 CHECK (revision >= 0), migrated_from_json_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS evolver.webui_controllers (
    id text PRIMARY KEY, public_key_fingerprint text, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS evolver.controller_projections (
    controller_id text PRIMARY KEY, public_key_fingerprint text, connection_state text, last_sync_at timestamptz,
    event_cursors jsonb NOT NULL DEFAULT '{}'::jsonb, telemetry_cursors jsonb NOT NULL DEFAULT '{}'::jsonb, projection jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS evolver.controller_credentials (
    controller_id text PRIMARY KEY REFERENCES evolver.controller_projections(controller_id) ON DELETE CASCADE, credential_digest text NOT NULL
);
CREATE TABLE IF NOT EXISTS evolver.controller_bindings (
    controller_id text PRIMARY KEY REFERENCES evolver.controller_projections(controller_id) ON DELETE CASCADE,
    webui_controller_id text NOT NULL REFERENCES evolver.webui_controllers(id), generation integer NOT NULL CHECK (generation > 0),
    server_url text NOT NULL, status text NOT NULL, bound_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS evolver.enrollment_tokens (
    token_digest text PRIMARY KEY, token_id text NOT NULL UNIQUE, server_url text NOT NULL, purpose text NOT NULL,
    expires_at timestamptz NOT NULL, used_at timestamptz
);
CREATE TABLE IF NOT EXISTS evolver.commands (
    command_id text PRIMARY KEY, controller_id text NOT NULL, generation integer NOT NULL, disposition text,
    requested_by text, auth_source text, requested_at timestamptz, command jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS evolver.command_acknowledgements (
    command_id text NOT NULL, controller_id text NOT NULL, acknowledged_at timestamptz NOT NULL DEFAULT now(),
    acknowledgement jsonb NOT NULL, PRIMARY KEY (command_id, controller_id)
);
CREATE TABLE IF NOT EXISTS evolver.handoff_history (
    id bigserial PRIMARY KEY, controller_id text NOT NULL, path text NOT NULL, occurred_at timestamptz NOT NULL, detail jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS evolver.recovery_metadata (
    controller_id text PRIMARY KEY, manifest jsonb, summary jsonb, updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS evolver_commands_delivery_idx ON evolver.commands (controller_id, generation, requested_at);
