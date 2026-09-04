CREATE TABLE IF NOT EXISTS system.runtime_metadata (
    key text PRIMARY KEY, value text NOT NULL, recorded_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO system.runtime_metadata (key, value)
VALUES ('initialized_at', now()::text), ('initialized_revision', coalesce(current_setting('meta_webui.source_revision', true), 'unknown'))
ON CONFLICT (key) DO NOTHING;
