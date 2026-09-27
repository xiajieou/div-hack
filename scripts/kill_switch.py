"""Submit the break-glass file. Owner: Ledger.

Holds no key: it reads break-glass/revoke.json (or BREAK_GLASS_FILE, the path the policy service and dashboard use),
checks it is this setup's revoke, submits it exactly as signed and reads the spend account back to confirm the desk
lost its permission. `make kill` does not load .env, and nothing here reads a seed or signs.

Exit codes: 0 revoked, 2 already used (tefNO_TICKET and the desk holds no permission), 1 anything else.

    make kill
"""
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xrpl.models.requests import AccountObjects  # noqa: E402

from fuse.breakglass import check_break_glass  # noqa: E402
from fuse.ledger.testnet import TestnetLedger  # noqa: E402

REVOKED, FAILED, ALREADY_USED = 0, 1, 2


def desk_permissions(ledger, spend, desk):
    # the ledger lists a Delegate entry under both accounts; only the spend account's own entry counts
    objs = ledger.client.request(AccountObjects(account=spend, ledger_index="validated", type="delegate")).result["account_objects"]
    return [p["Permission"]["PermissionValue"] for o in objs
            if o["Account"] == spend and o["Authorize"] == desk for p in o["Permissions"]]


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    path = Path(os.environ.get("BREAK_GLASS_FILE", ROOT / "break-glass" / "revoke.json"))
    accounts_path = ROOT / "env" / "accounts.json"
    if not path.exists() or not accounts_path.exists():
        print(f"missing {path if not path.exists() else accounts_path}; run scripts/setup_testnet.py first")
        return FAILED
    accounts = json.loads(accounts_path.read_text())
    spend, desk = accounts["spend"], accounts["desk"]
    tx = json.loads(path.read_text())

    problems = check_break_glass(tx, spend, desk)
    if problems:
        print(f"refusing to submit {path}:")
        for p in problems:
            print(f"  {p}")
        return FAILED

    ledger = TestnetLedger(accounts["rpc"])
    print(f"network {accounts['network']}   spend {spend}   desk {desk}   ticket {tx['TicketSequence']}")
    print(f"desk permissions before: {desk_permissions(ledger, spend, desk) or 'none'}")
    r = ledger.submit(tx)
    print(f"submitted {path.name}: {r.engine_result}  {r.message}")
    after = desk_permissions(ledger, spend, desk)
    print(f"desk permissions after:  {after or 'none'}")

    if after:
        # whatever the code said, the desk can still pay: the kill switch did not work
        print("NOT REVOKED: the desk still holds a permission. Revoke by hand with the spend key (DelegateSet, empty Permissions).")
        return FAILED
    if r.engine_result == "tefNO_TICKET":
        print("Already used: this file's ticket is gone and the desk holds no permission. Re-run setup to re-arm.")
        return ALREADY_USED
    if r.ok:
        print(f"Desk revoked. Every payment through the desk now fails with terNO_DELEGATE_PERMISSION. {ledger.explorer}/accounts/{spend}")
        return REVOKED
    print(f"Unexpected result {r.engine_result}; the desk holds no permission, but check {ledger.explorer}/accounts/{spend}")
    return FAILED


if __name__ == "__main__":
    sys.exit(main())
