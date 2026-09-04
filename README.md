# evolver-server

Central eVOLVER control service extracted from the reference backend. It owns
central state and PostgreSQL persistence through `DATABASE_URL`, retaining the
JSON bootstrap seam used by tests and migration. It does not load Meta WebUI
frontend/catalog code or BAL schema source.

Origin: Meta WebUI `wire-in-cli` `652cc5d`.
