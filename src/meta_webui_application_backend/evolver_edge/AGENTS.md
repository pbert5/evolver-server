# eVOLVER edge runtime

The edge owns durable deployed state, local operation, event journal, telemetry
spool, recovery manifests, simulator, CLI/TUI, and the hardware-service
boundary. Preserve safe offline continuation and restore operational control
before reconciliation. Never use `/dev/tty*`, USB order, or VID/PID as durable
identity. Higher layers must not compete for the physical serial port. Keep
firmware updates distinct from ordinary software updates and keep tests
non-actuating.
