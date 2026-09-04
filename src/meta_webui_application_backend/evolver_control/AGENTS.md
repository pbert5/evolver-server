# eVOLVER control plane

Central owns future intent and durable coordination: enrollment, credentials,
ControllerGeneration fencing, command queues, sync, revision conflicts,
deployment queues, interventions, and PostgreSQL persistence. Commands are
intent; ACKs are protocol evidence, not physical evidence. Keep mutable run
operations revision-fenced and never move authority into process-local memory.
Coordinate with `evolver_edge` for offline/recovery semantics.
