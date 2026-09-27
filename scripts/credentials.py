"""Vendor credentials on the network the setup script created. Owner: whoever finishes first.

The registry issues a "verified-vendor" credential to each listed vendor and to Northwind Freight (CredentialCreate),
and each accepts it (CredentialAccept). Northwind is verified but not on the company's list: a human still has to
approve it before it can be paid. The attacker gets none. Addresses come from env/accounts.json; the registry and vendor seeds
come from the environment (`make credentials` loads .env). Every result code is printed; tecDUPLICATE means the step
was already done, so the script can be re-run.

    make credentials
"""
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xrpl.wallet import Wallet  # noqa: E402

from fuse.ledger.testnet import TestnetLedger  # noqa: E402
from fuse.registry import accept, issue  # noqa: E402

DONE = ("tesSUCCESS", "tecDUPLICATE")


def seed_name(vendor: str) -> str:
    return "VENDOR_" + re.sub(r"[^A-Z0-9]+", "_", vendor.upper()).strip("_") + "_SEED"


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    accounts = json.loads((ROOT / "env" / "accounts.json").read_text())
    ledger = TestnetLedger(accounts["rpc"])
    registry = Wallet.from_seed(os.environ["REGISTRY_SEED"])
    if registry.classic_address != accounts["registry"]:
        sys.exit("REGISTRY_SEED does not match env/accounts.json; re-run setup or reload .env")
    print(f"network: {accounts['network']}   registry {registry.classic_address}")
    failed = []
    vendors = {**accounts["vendors"], "Northwind Freight": accounts["northwind"]}
    seeds = {name: seed_name(name) for name in accounts["vendors"]} | {"Northwind Freight": "NORTHWIND_SEED"}
    for name, address in vendors.items():
        seed = os.environ.get(seeds[name])
        if not seed:
            print(f"  {name:22} skipped: {seeds[name]} is not set")
            failed.append(name)
            continue
        created = issue(ledger, registry, address)
        accepted = accept(ledger, Wallet.from_seed(seed), registry.classic_address) if created.engine_result in DONE else None
        print(f"  {name:22} issue {created.engine_result:15} accept {accepted.engine_result if accepted else '-'}")
        if not accepted or accepted.engine_result not in DONE:
            failed.append(name)
    print("  attacker               no credential, on purpose")
    if failed:
        sys.exit(f"not credentialed: {failed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
