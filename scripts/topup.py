"""Human-signed top-up of the spend account from the treasury. Owner: Ledger. Used in demo scene 5.

Run by a person, never by a service: it reads TREASURY_SEED from the environment of whoever runs it, or from .env
when that is not set, and sends XRP from the treasury to the spend account named in env/accounts.json. The flow
view's Top up button starts this script as its own process, so the flow server never loads the treasury key.

    make topup                      # 30 XRP
    python scripts/topup.py 12.5
"""
import json
import os
import sys
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from xrpl.models.transactions import Payment  # noqa: E402
from xrpl.transaction import autofill_and_sign  # noqa: E402
from xrpl.wallet import Wallet  # noqa: E402

from fuse.config import xrp_to_drops  # noqa: E402
from fuse.ledger.testnet import TestnetLedger  # noqa: E402


def treasury_seed() -> str:
    if os.environ.get("TREASURY_SEED"):
        return os.environ["TREASURY_SEED"]
    env = ROOT / ".env"
    for line in env.read_text().splitlines() if env.exists() else []:
        key, _, value = line.partition("=")
        if key.strip() == "TREASURY_SEED" and value.strip():
            return value.split("#")[0].strip()
    sys.exit("TREASURY_SEED is not set and not in .env; run scripts/setup_testnet.py first")


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8")
    amount = Decimal(sys.argv[1]) if len(sys.argv) > 1 else Decimal("30")
    accounts = json.loads((ROOT / "env" / "accounts.json").read_text())
    treasury = Wallet.from_seed(treasury_seed())
    if treasury.classic_address != accounts["treasury"]:
        sys.exit("TREASURY_SEED does not match env/accounts.json; re-run setup or reload .env")
    ledger = TestnetLedger(accounts["rpc"])
    tx = Payment(account=treasury.classic_address, destination=accounts["spend"], amount=xrp_to_drops(amount))
    r = ledger.submit(autofill_and_sign(tx, ledger.client, treasury).to_xrpl())
    print(f"top-up {amount} XRP treasury -> spend   {r.engine_result}   {ledger.explorer}/transactions/{r.hash}")
    print(f"spend balance now {ledger.balance_xrp(accounts['spend'])} XRP")
    return 0 if r.ok else 1


if __name__ == "__main__":
    sys.exit(main())
