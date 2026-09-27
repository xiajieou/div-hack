"""Blast radius report: the worst case per compromised part, and the setup findings that would invalidate it.

    python -m fuse.reports.blast_radius --mode local|testnet|devnet [--json]

blast_radius() is pure: a snapshot of ledger state in, rows and findings out. The snapshot looks like this:

    snapshot = {
        "float_drops": 30_000_000,                 # spend account balance
        "spend": {
            "address": "rSpend...",
            "delegations": {"rDesk...": ["Payment"]},   # delegate address -> granted permissions
            "regular_key": None,
            "master_disabled": False,
            "signers": {},                              # a signer list on the spend account is another way in
        },
        "desk": {
            "quorum": 2,
            "signers": {"rAgent...": 1, "rPolicy...": 1},
            "regular_key": None,
            "master_disabled": True,
        },
        "treasury": {"address": "rTreasury...", "delegations": {}},
        "treasury_drops": 250_000_000,
    }

Findings: more than one delegate, a delegate holding anything besides Payment, a regular key on the spend account
or the desk, a signer list on the spend account, the desk master key enabled, a desk quorum below the total signer
weight, any delegate on the treasury, or payments coming straight from the treasury. Any finding raises every
program-held key's row to the float, because the argument no longer holds. Whoever can sign for the desk can also
spend the desk's own XRP (its fee budget), so that balance is added wherever the desk's keys are enough. With no
delegation left (the kill switch fired) and no findings, both keys together can move only the desk's own balance.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from typing import List, Tuple

from ..config import drops_to_xrp


@dataclass
class Row:
    part: str
    max_loss_drops: int
    why: str


@dataclass
class Finding:
    text: str


def blast_radius(snapshot: dict) -> Tuple[List[Row], List[Finding]]:
    spend, desk = snapshot["spend"], snapshot["desk"]
    treasury = snapshot.get("treasury") or {}
    float_drops = snapshot["float_drops"]
    findings: List[Finding] = []

    delegations = spend["delegations"]
    if len(delegations) > 1:
        findings.append(Finding(f"spend account has {len(delegations)} delegates: {sorted(delegations)}"))
    for delegate, perms in delegations.items():
        extra = sorted(set(perms) - {"Payment"})
        if extra:
            findings.append(Finding(f"delegate {delegate} holds permissions beyond Payment: {extra}"))

    for name, acct in (("spend account", spend), ("desk", desk)):
        if acct["regular_key"]:
            findings.append(Finding(f"{name} has a regular key: {acct['regular_key']}"))
    if spend.get("signers"):
        findings.append(Finding(f"spend account has a signer list: {sorted(spend['signers'])}"))
    if not desk["master_disabled"]:
        findings.append(Finding("desk master key is not disabled"))

    total_weight = sum(desk["signers"].values())
    if desk["quorum"] < total_weight:
        findings.append(Finding(f"desk quorum {desk['quorum']} is below total signer weight {total_weight}: fewer than all keys can sign"))

    if treasury.get("address") and treasury["address"] == spend.get("address"):
        findings.append(Finding("payments come straight from the treasury: no separate spend account caps the loss"))
    elif treasury.get("delegations"):
        findings.append(Finding(f"treasury has delegates: {sorted(treasury['delegations'])}"))

    desk_drops = desk.get("balance_drops", 0)
    one_key = float_drops + desk_drops if findings else 0
    both_keys = (float_drops if delegations or findings else 0) + desk_drops
    broken = "a setup finding voids the two-key argument; assume the worst"
    desk_note = f" plus the desk's own {drops_to_xrp(desk_drops)} XRP" if desk_drops else ""
    rows = [
        Row("reader", 0, "files intents only; holds no key"),
        Row("agent key", one_key, broken if findings else "quorum also needs the policy signature"),
        Row("policy key", one_key, broken if findings else "quorum also needs the agent signature; the daemon signs only matching intents"),
        Row("agent+policy keys", both_keys,
            ("delegation covers Payment only; the ledger caps it at the spend balance" if delegations or findings
             else "no delegation on the spend account: nothing from it") + desk_note),
        Row("spend account key", float_drops, "controls the spend account and nothing else"),
        Row("treasury key", snapshot["treasury_drops"], "everything; human-only key"),
    ]
    return rows, findings


def read_snapshot(source, addresses: dict) -> dict:
    spend = source.facts(addresses["spend"])
    desk = source.facts(addresses["desk"])
    treasury = spend if addresses["treasury"] == addresses["spend"] else source.facts(addresses["treasury"])
    return {"float_drops": spend["balance_drops"], "treasury_drops": treasury["balance_drops"],
            "spend": spend, "desk": desk, "treasury": treasury}


def _xrp(drops: int) -> str:
    return f"{drops_to_xrp(drops)} XRP"


def print_report(snapshot: dict, rows: List[Row], findings: List[Finding], where: str) -> None:
    print(f"Blast radius, read from {where}\n\nAccounts")
    for name in ("spend", "desk", "treasury"):
        a = snapshot[name]
        if name == "treasury" and a is snapshot["spend"]:
            print(f"  treasury  {a['address']}  (the same account as spend)")
            continue
        print(f"  {name:<9} {a['address']}  balance {_xrp(a['balance_drops'])}")
        print(f"            master key {'disabled' if a['master_disabled'] else 'enabled'}, regular key {a['regular_key'] or 'none'}")
        if a["signers"]:
            print(f"            signer list quorum {a['quorum']}: " + ", ".join(f"{s} (w{w})" for s, w in a["signers"].items()))
        else:
            print("            signer list none")
        for d, perms in a["delegations"].items():
            print(f"            delegate {d}: {', '.join(perms) or 'nothing'}")
        if not a["delegations"]:
            print("            delegates none")
    print("\nWorst case per compromised part")
    for r in rows:
        print(f"  {r.part:<18} {_xrp(r.max_loss_drops):>18}   {r.why}")
    print("\nFindings")
    for f in findings:
        print(f"  ! {f.text}")
    if not findings:
        print("  none")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Fuse blast radius report")
    ap.add_argument("--mode", choices=["local", "testnet", "devnet"], default="local")
    ap.add_argument("--treasury")
    ap.add_argument("--spend", help="the account the payments are sent from")
    ap.add_argument("--desk")
    ap.add_argument("--json", action="store_true", help="print JSON instead of the table")
    args = ap.parse_args(argv)

    from .sources import LocalWorld, Network, load_addresses
    if args.mode == "local":
        world = LocalWorld(attack=False)
        source, addresses, where = world, world.addresses, "a fresh local ledger (setup and three clean payments)"
    else:
        source = Network(args.mode)
        addresses = load_addresses({"treasury": args.treasury, "spend": args.spend, "desk": args.desk})
        where = f"XRPL {args.mode}, {source.explorer}"

    snapshot = read_snapshot(source, addresses)
    rows, findings = blast_radius(snapshot)
    if args.json:
        print(json.dumps({"mode": args.mode, "snapshot": snapshot, "rows": [asdict(r) for r in rows],
                          "findings": [f.text for f in findings]}, indent=2))
    else:
        print_report(snapshot, rows, findings, where)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
