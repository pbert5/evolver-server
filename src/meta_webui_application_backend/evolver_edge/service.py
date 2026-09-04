"""Long-running controller process entrypoint used by the systemd unit."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

from .store import EdgeStore
from .sync import SyncClient


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="evolver-controller")
    parser.add_argument("--state-root", default=os.environ.get("EVOLVER_STATE_ROOT", "/var/lib/evolver-controller"))
    parser.add_argument("--interval", type=float, default=10.0)
    parser.add_argument("--simulator-instruments", type=int, default=0,
                        help="publish this many safe simulated instruments on every sync")
    args = parser.parse_args(argv)
    # SyncClient has bounded exponential retry.  State is entirely below the
    # StateDirectory, so service restarts cannot recreate identity or bindings.
    with EdgeStore(Path(args.state_root)) as store:
        # Inventory is shared durable edge state.  The optional simulator and
        # the exclusive read-only hardware service both populate it, so sync
        # must never hide physical observations when simulator is disabled.
        inventory = store.list_instruments
        if args.simulator_instruments:
            if args.simulator_instruments < 1:
                parser.error("--simulator-instruments must be positive")
            # The simulator only writes the durable Instrument contract and
            # never opens a serial device or performs physical actuation.
            from .simulator import EvolverSimulator
            simulator = EvolverSimulator(store, instruments=args.simulator_instruments)
            # Instantiate once to register stable simulated identities; the
            # common store inventory keeps physical and simulated instruments.
            simulator.inventory()
        SyncClient(store).run_loop(interval=args.interval, inventory=inventory)
    return 0


if __name__ == "__main__":  # pragma: no cover - console entry point
    raise SystemExit(main())
