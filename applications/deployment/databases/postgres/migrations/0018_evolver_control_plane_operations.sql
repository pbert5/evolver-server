CREATE TABLE IF NOT EXISTS evolver.manual_control_leases (
    lease_id text PRIMARY KEY, controller_id text NOT NULL, controller_generation integer NOT NULL CHECK (controller_generation > 0), holder text NOT NULL,
    acquired_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, revoked_at timestamptz, revoked_by text, status text NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS evolver_active_manual_control_lease_idx ON evolver.manual_control_leases (controller_id) WHERE status = 'active' AND revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS evolver.controller_endpoint_assignments (
    controller_id text PRIMARY KEY, endpoint_id text NOT NULL, endpoint_url text NOT NULL, assigned_at timestamptz NOT NULL, assigned_by text NOT NULL
);
CREATE TABLE IF NOT EXISTS evolver.control_audit_events (
    event_id text PRIMARY KEY, event_type text NOT NULL, occurred_at timestamptz NOT NULL, actor text, details jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE TABLE IF NOT EXISTS evolver.rollback_requests (
    request_id text PRIMARY KEY, controller_id text NOT NULL, controller_generation integer NOT NULL CHECK (controller_generation > 0), release_id text NOT NULL,
    requested_at timestamptz NOT NULL, requested_by text NOT NULL, auth_source text NOT NULL, reason text NOT NULL, status text NOT NULL, idempotency_key text UNIQUE
);
