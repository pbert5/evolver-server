# evolver-server

Central eVOLVER control service extracted from the reference backend. It owns
central state and PostgreSQL persistence through `DATABASE_URL`, retaining the
JSON bootstrap seam used by tests and migration. It does not load Meta WebUI
frontend/catalog code or BAL schema source.

Origin: Meta WebUI `wire-in-cli` `652cc5d`.

## Operator contract

The canonical machine contract is packaged at
`evolver_server/contracts/operator_actions.json`. The executable adapter
registry in `evolver_server.control.actions` remains authoritative for
callability; planned actions are discoverable but are not dispatchable.

Export the canonical deterministic snapshot with:

```bash
python -m evolver_server.control.contract
```
