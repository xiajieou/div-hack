"""Submit the break-glass file. Owner: Ledger. Holds no key: it reads break-glass/revoke.json and submits it.

The file is a DelegateSet with no permissions, pre-signed by the spend account against a Ticket at setup, so it
removes the desk's authority without anyone holding a key at that moment. Its Ticket is used up when it lands;
a second submit returns the ledger's code for that, printed as is.

    make kill
"""
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fuse.ledger.testnet import TestnetLedger  # noqa: E402


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    path = Path(os.environ.get("BREAK_GLASS_FILE", ROOT / "break-glass" / "revoke.json"))
    blob = json.loads(path.read_text())
    accounts = json.loads((ROOT / "env" / "accounts.json").read_text())
    ledger = TestnetLedger(accounts["rpc"])
    r = ledger.submit(blob)
    print(f"break-glass: revoke the desk {blob['Authorize']} on {blob['Account']}   {r.engine_result}")
    print(f"  {ledger.explorer}/transactions/{r.hash}" if r.validated else f"  {r.message}")
    return 0 if r.ok else 1


if __name__ == "__main__":
    sys.exit(main())
