# Central protocol compatibility inventory

This inventory records duplicate fields at the server/controller boundary.
Compatibility fields are retained only where the current edge protocol still
sends them; normalized PostgreSQL columns are the durable authority.

| Field pair | Current consumer | Decision |
| --- | --- | --- |
| `hardware_observation` / `detected_hardware` | Older edge sync payloads use `detected_hardware`; current sync uses the typed observation | Keep `detected_hardware` as a temporary input compatibility field. It is normalized into `hardware_observation` and is never emitted as a second durable projection. Remove after the supported edge protocol floor no longer sends it. |
| `captured_at` / `timestamp` / `at` | Telemetry normalizer accepts historical edge spellings | Keep as input aliases at the parser boundary; persist only `captured_at`. |
| `instrument_id` / `evolver_id` | Historical telemetry records use `evolver_id` | Keep `evolver_id` as an input alias; persist `instrument_id`. |
| `event_type` / `type` and `occurred_at` / `at` | Calibration/history compatibility payloads | Keep parser aliases for supported payload versions; persist canonical `event_type` and `occurred_at`. |
| `controller_generation` / binding `generation` | Sync request versus normalized binding relation | Keep both at their protocol/domain boundaries; the normalized binding `generation` is authoritative for fencing. |
| `command_acknowledgements` / controller `acknowledgements` | Edge sync input versus central projection | Keep input name and internal aggregate name; persist acknowledgement rows keyed by command/controller. |

No duplicate field is emitted solely to satisfy a test. Protocol-visible
removals require a versioned edge compatibility fixture and a supported-client
inventory update.
