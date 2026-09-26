"""Blast radius report: the worst case per compromised part, and the setup findings that would invalidate it.

blast_radius() is pure: a snapshot of ledger state in, rows and findings out. The snapshot looks like this:

    snapshot = {
        "float_drops": 30_000_000,                 # spend account balance
        "spend": {
            "delegations": {"rDesk...": ["Payment"]},   # delegate address -> granted permissions
            "regular_key": None,
            "master_disabled": False,
        },
        "desk": {
            "quorum": 2,
            "signers": {"rAgent...": 1, "rPolicy...": 1},
            "regular_key": None,
            "master_disabled": True,
        },
        "treasury_drops": 250_000_000,
    }

Findings: more than one delegate, a delegate holding anything besides Payment, a regular key on the spend account
or the desk, the desk master key enabled, or a desk quorum below the total signer weight. Any finding raises the
single-key rows to the float, because the two-key argument no longer holds.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple


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
    if not desk["master_disabled"]:
        findings.append(Finding("desk master key is not disabled"))

    total_weight = sum(desk["signers"].values())
    if desk["quorum"] < total_weight:
        findings.append(Finding(f"desk quorum {desk['quorum']} is below total signer weight {total_weight}: fewer than all keys can sign"))

    one_key = float_drops if findings else 0
    rows = [
        Row("reader", 0, "files intents only; holds no key"),
        Row("agent key", one_key, "setup findings break the two-key argument" if findings else "quorum also needs the policy signature"),
        Row("policy key", one_key, "setup findings break the two-key argument" if findings else "quorum also needs the agent signature; the daemon signs only matching intents"),
        Row("agent+policy keys", float_drops, "delegation covers Payment only; the ledger caps it at the spend balance"),
        Row("spend account key", float_drops, "controls the spend account and nothing else"),
        Row("treasury key", snapshot["treasury_drops"], "everything; human-only key"),
    ]
    return rows, findings
