"""Exercise 2: the audit completeness check.

The log proves nothing was edited; this proves nothing was left out.

Input:
    history: a list of ledger transactions for the spend account, each a dict with
             {"type": "Payment"|..., "account": str, "delegate": str|None, "destination": str,
              "result": "tesSUCCESS"|"tec..."|..., "hash": str, "amount_drops": int}
             It includes incoming payments (account != spend), failed attempts (tec results),
             setup transactions, and the attacker's payments.
    log_tx_hashes: the set of transaction hashes the audit log has a "result" row for.
    spend_address: the spend account's address.

Definition (DECISIONS.md D5): a "real payment" is an OUTGOING Payment (account == spend_address)
with result tesSUCCESS. Incoming top-ups, failed attempts and non-Payment transactions are ignored.
Do not filter by SourceTag; an attacker will not tag anything.

Output: the list of real payments (as the input dicts) that have no matching log entry, in history order.

Implement unlogged_payments(). The tests are already written.
"""
from __future__ import annotations

from typing import Iterable, List, Set


def unlogged_payments(history: Iterable[dict], log_tx_hashes: Set[str], spend_address: str) -> List[dict]:
    raise NotImplementedError("your exercise: implement unlogged_payments")
