"""Break-glass file: the pre-signed kill switch.

A DelegateSet with empty Permissions, pre-signed by the spend account against a Ticket, valid forever, that anyone
can submit to revoke the desk without holding a key at that moment. Setup creates the Ticket (TicketCreate on the
spend account), signs this transaction and writes it to break-glass/revoke.json. scripts/kill_switch.py and the
dashboard submit that file; neither holds a key.

Mechanics (xrpl-py 5.x):
    - A transaction that uses a Ticket sets Sequence to 0 and TicketSequence to the ticket's number.
    - It must not carry LastLedgerSequence, or it expires.
    - Fee should be generous (>= 1000 drops) because network fees can rise and the file never expires.
    - Sign it with the spend account's wallet: xrpl.transaction.sign(tx_model, wallet) -> signed model; .to_xrpl() -> dict.

build_break_glass() returns the UNSIGNED transaction dict; sign_break_glass() returns the signed dict the file stores.
"""
from __future__ import annotations

from xrpl.models.transactions import DelegateSet
from xrpl.transaction import sign
from xrpl.wallet import Wallet


def build_break_glass(spend_address: str, desk_address: str, ticket_sequence: int, fee_drops: int = 1000) -> dict:
    # no autofill: it would replace Sequence 0 and add a LastLedgerSequence, and the file must never expire
    tx = DelegateSet(account=spend_address, authorize=desk_address, permissions=[],
                     sequence=0, ticket_sequence=ticket_sequence, fee=str(fee_drops))
    return tx.to_xrpl()


def sign_break_glass(spend_wallet: Wallet, desk_address: str, ticket_sequence: int, fee_drops: int = 1000) -> dict:
    unsigned = build_break_glass(spend_wallet.classic_address, desk_address, ticket_sequence, fee_drops)
    return sign(DelegateSet.from_xrpl(unsigned), spend_wallet).to_xrpl()
