ALTER TABLE evolver.commands ADD COLUMN IF NOT EXISTS expires_at timestamptz;
ALTER TABLE evolver.commands ADD COLUMN IF NOT EXISTS expired_at timestamptz;
ALTER TABLE evolver.commands ADD COLUMN IF NOT EXISTS acknowledged_at timestamptz;
