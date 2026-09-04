ALTER TABLE evolver.commands ADD COLUMN IF NOT EXISTS delivery_eligible boolean NOT NULL DEFAULT true;
