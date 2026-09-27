"""Dashboard on a local ledger, no network.

    python -m dashboard.serve [--port 8001]      then open http://localhost:8001/dashboard

Runs the demo invoices through the real policy service and signer daemon, plus two stolen-key attacks, then serves
the policy API with the dashboard. Northwind Freight is left parked so the Add vendor form has something to do;
its address is printed below. On a real network, run the policy service instead and open /dashboard on it.
"""
from __future__ import annotations

import argparse
import sys
import tempfile
from decimal import Decimal

import uvicorn

from fuse.policy.api import create_app
from fuse.reader.reader import write_fixtures
from fuse.reports.api import add_routes
from fuse.reports.sources import LocalWorld

INVOICES = ["inv_2201_verdant.txt", "inv_7734_harbor.txt", "inv_0092_lumen.txt", "inv_2201_verdant_REISSUE.txt",
            "inv_9001_lumen_prepay.txt", "inv_5510_northwind.txt"]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Fuse dashboard on a local ledger")
    ap.add_argument("--port", type=int, default=8001)
    args = ap.parse_args(argv)

    world = LocalWorld(invoices=[])
    northwind = world.ring.northwind.classic_address
    world.daemon.add_vendor("Northwind Freight", northwind)   # the human's step on the daemon side, done at setup
    for name in INVOICES:
        world.process(name)
    world.agent_key_alone(Decimal("50"))
    world.stolen_keys(Decimal("50"), 2)

    inbox = tempfile.mkdtemp(prefix="fuse-inbox-")
    write_fixtures(inbox, world.ring.attacker.classic_address)
    app = create_app(world.service)
    add_routes(app, world.service, world.addresses, inbox)

    print(f"Dashboard: http://localhost:{args.port}/dashboard", flush=True)
    print(f"Northwind Freight is parked. To add it: name Northwind Freight, address {northwind}, jurisdiction US", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
