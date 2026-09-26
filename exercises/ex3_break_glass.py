"""Exercise 3: the break-glass file.

A DelegateSet with empty Permissions, pre-signed by the spend account against a Ticket, valid forever,
that anyone can submit to revoke the desk without holding a key at that moment.

Mechanics you need (xrpl-py 5.x):
    - A transaction that uses a Ticket sets Sequence to 0 and TicketSequence to the ticket's number.
    - It must not carry LastLedgerSequence, or it expires.
    - Fee should be generous (>= 1000 drops) because network fees can rise and the file never expires.
    - Sign it with the spend account's wallet: xrpl.transaction.sign(tx_model, wallet) -> signed model; .to_xrpl() -> dict.

Implement build_break_glass(): return the UNSIGNED transaction dict.
Implement sign_break_glass(): return the signed transaction dict (what the file stores).
The tests are already written and run offline.
"""
from __future__ import annotations

from xrpl.wallet import Wallet


def build_break_glass(spend_address: str, desk_address: str, ticket_sequence: int, fee_drops: int = 1000) -> dict:
    raise NotImplementedError("your exercise: implement build_break_glass")


def sign_break_glass(spend_wallet: Wallet, desk_address: str, ticket_sequence: int, fee_drops: int = 1000) -> dict:
    raise NotImplementedError("your exercise: implement sign_break_glass")
