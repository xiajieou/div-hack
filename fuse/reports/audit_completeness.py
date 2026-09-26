"""Audit completeness check. The hash chain proves nothing was edited; this proves nothing was left out.

unlogged_payments() is pure. history is the spend account's ledger transactions, each a dict with
{"type", "account", "delegate", "destination", "result", "hash", "amount_drops"}; log_tx_hashes is the set of
transaction hashes the audit log has a result row for.

A real payment is an outgoing Payment (account == spend_address) with result tesSUCCESS. Incoming top-ups, failed
attempts and other transaction types are ignored. It does not filter by SourceTag: an attacker will not tag anything.
Returns the real payments with no log entry, in history order.
"""
from __future__ import annotations

from typing import Iterable, List, Set


def unlogged_payments(history: Iterable[dict], log_tx_hashes: Set[str], spend_address: str) -> List[dict]:
    return [tx for tx in history
            if tx["type"] == "Payment" and tx["account"] == spend_address
            and tx["result"] == "tesSUCCESS" and tx["hash"] not in log_tx_hashes]
