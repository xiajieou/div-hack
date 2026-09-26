"""Audit completeness check. The hash chain proves nothing was edited; this proves nothing was left out.

    python -m fuse.reports.audit_completeness --mode local|testnet|devnet [--spend r...] [--log audit.json] [--json]

unlogged_payments() is pure. history is the spend account's ledger transactions, each a dict with
{"type", "account", "delegate", "destination", "result", "hash", "amount_drops"}; log_tx_hashes is the set of
transaction hashes the audit log has a result row for.

A real payment is an outgoing Payment (account == spend_address) with result tesSUCCESS. Incoming top-ups, failed
attempts and other transaction types are ignored. It does not filter by SourceTag: an attacker will not tag anything.
Returns the real payments with no log entry, in history order.

On testnet or devnet the audit rows come from --log (a JSON list of AuditChain.dump() rows) or from the policy
service's GET /status ("audit" field) at POLICY_URL.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Iterable, List, Set


def unlogged_payments(history: Iterable[dict], log_tx_hashes: Set[str], spend_address: str) -> List[dict]:
    return [tx for tx in history
            if tx["type"] == "Payment" and tx["account"] == spend_address
            and tx["result"] == "tesSUCCESS" and tx["hash"] not in log_tx_hashes]


def _audit_rows(log_path: str | None) -> List[dict]:
    if log_path:
        with open(log_path) as f:
            return json.load(f)
    import httpx
    url = os.environ.get("POLICY_URL", "http://localhost:8001") + "/status"
    try:
        return httpx.get(url, timeout=10).raise_for_status().json()["audit"]
    except httpx.HTTPError as e:
        raise SystemExit(f"could not read the audit log from {url}: {e}. Pass --log with a saved copy instead.")


def print_report(history: List[dict], logged: Set[str], missing: List[dict], spend: str, where: str, explorer: str) -> None:
    outgoing = [t for t in history if t["type"] == "Payment" and t["account"] == spend and t["result"] == "tesSUCCESS"]
    print(f"Audit completeness, read from {where}\n")
    print(f"  spend account                      {spend}")
    print(f"  transactions in its history        {len(history)}")
    print(f"  successful outgoing payments       {len(outgoing)}")
    print(f"  of those, in the audit log         {len(outgoing) - len(missing)}")
    print(f"  of those, NOT in the audit log     {len(missing)}")
    for t in missing:
        print(f"\n  ! {t['amount']} to {t['destination']}" + (f" via delegate {t['delegate']}" if t["delegate"] else ""))
        print(f"    tx {t['hash']}")
        if explorer:
            print(f"    {explorer}/transactions/{t['hash']}")
    if not missing:
        print("\n  every payment that left the spend account is in the log")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Fuse audit completeness check")
    ap.add_argument("--mode", choices=["local", "testnet", "devnet"], default="local")
    ap.add_argument("--spend", help="the account the payments are sent from")
    ap.add_argument("--log", help="JSON file of audit rows (testnet/devnet); default: GET POLICY_URL/status")
    ap.add_argument("--json", action="store_true", help="print JSON instead of the summary")
    args = ap.parse_args(argv)

    from .sources import LocalWorld, Network, load_addresses, log_hashes
    if args.mode == "local":
        world = LocalWorld(attack=True)
        spend, source, logged, explorer = world.addresses["spend"], world, world.log_hashes(), ""
        where = "a fresh local ledger (setup, three clean payments, then an attacker with both keys)"
    else:
        source = Network(args.mode)
        spend = args.spend or load_addresses({})["spend"]
        logged, explorer, where = log_hashes(_audit_rows(args.log)), source.explorer, f"XRPL {args.mode}, {source.explorer}"

    history = source.history(spend)
    missing = unlogged_payments(history, logged, spend)
    if args.json:
        print(json.dumps({"mode": args.mode, "spend": spend, "history": history, "unlogged": missing}, indent=2))
    else:
        print_report(history, logged, missing, spend, where, explorer)
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main())
