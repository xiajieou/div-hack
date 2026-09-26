"""Exercise 1: the blast radius report.

Input: a plain snapshot of ledger state (no network), shaped like this:

    snapshot = {
        "float_drops": 30_000_000,                 # spend account balance
        "spend": {
            "delegations": {"rDesk...": ["Payment"]},   # delegate address -> granted permissions
            "regular_key": None,                        # set if a RegularKey exists on the spend account
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

Output: a list of Row(part, max_loss_drops, why) for these parts, in this order:
    "reader", "agent key", "policy key", "agent+policy keys", "spend account key", "treasury key"
plus a list of Finding(text) for anything that makes the number untrustworthy:
    - a delegate holding any permission other than Payment
    - more than one delegate
    - a regular key on the desk or the spend account
    - desk master key not disabled
    - desk quorum lower than the number of signers (one key would be enough)
When findings exist, every program-held key's max loss becomes the float (the argument no longer holds).

Rules of the table (from SPEC.md, "Worst case per compromised key"):
    reader                0
    agent key             0             (quorum needs the policy signature)
    policy key            0             (quorum needs the agent signature; the daemon won't sign a mismatch)
    agent+policy keys     float         (payments only; ledger caps the amount)
    spend account key     float
    treasury key          treasury_drops

Implement blast_radius(). The tests in tests/test_ex1_blast_radius.py are already written.
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
    raise NotImplementedError("your exercise: implement blast_radius")
